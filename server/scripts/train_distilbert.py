"""Train and export a DistilBERT prompt-injection classifier.

The script intentionally keeps dataset preparation and artifact metadata in one
place so a trained model can be reproduced and loaded by the API detector.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SAFE_LABEL = 0
MALICIOUS_LABEL = 1
DATASET_SOURCES = (
    "deepset/prompt-injections",
    "jackhhao/jailbreak-classification",
    "neuralchemy/Prompt-injection-dataset",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model-name", default="distilbert-base-uncased")
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--epochs", type=float, default=3)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--train-batch-size", type=int, default=16)
    parser.add_argument("--eval-batch-size", type=int, default=32)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--test-size", type=float, default=0.15)
    parser.add_argument("--validation-size", type=float, default=0.1)
    parser.add_argument("--skip-training", action="store_true")
    return parser.parse_args()


def set_seed(seed: int) -> None:
    import numpy as np

    random.seed(seed)
    np.random.seed(seed)


def _column(frame: Any, names: tuple[str, ...]) -> str:
    for name in names:
        if name in frame.columns:
            return name
    raise ValueError(f"Dataset is missing one of the expected columns: {names}")


def _normalize_label(value: Any, source: str) -> int:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"0", "safe", "benign", "normal", "legitimate"}:
            return SAFE_LABEL
        if normalized in {"1", "malicious", "injection", "jailbreak", "attack"}:
            return MALICIOUS_LABEL
    if value in (SAFE_LABEL, MALICIOUS_LABEL):
        return int(value)
    raise ValueError(f"Unsupported label {value!r} in {source}")


def _frame_from_dataset(dataset: Any, source: str) -> Any:
    import pandas as pd

    frame = dataset.to_pandas() if hasattr(dataset, "to_pandas") else pd.DataFrame(dataset)
    text_column = _column(frame, ("text", "prompt", "instruction", "content"))
    label_column = _column(frame, ("label", "labels", "type", "class"))
    output = pd.DataFrame(
        {
            "text": frame[text_column].astype("string"),
            "label": [
                _normalize_label(value, source)
                for value in frame[label_column].tolist()
            ],
            "source": source,
        }
    )
    output = output.dropna(subset=["text"])
    output["text"] = output["text"].str.replace(r"\s+", " ", regex=True).str.strip()
    return output[output["text"].str.len() > 0]


def load_and_prepare_data() -> tuple[Any, dict[str, Any]]:
    from datasets import load_dataset
    import pandas as pd

    frames: list[Any] = []
    for source in DATASET_SOURCES:
        config = "full" if source == "neuralchemy/Prompt-injection-dataset" else None
        loaded = load_dataset(source, config) if config else load_dataset(source)
        split = loaded["train"] if "train" in loaded else loaded[next(iter(loaded))]
        frames.append(_frame_from_dataset(split, source))

    combined = pd.concat(frames, ignore_index=True)
    before = len(combined)
    combined = combined.drop_duplicates(subset=["text"]).reset_index(drop=True)
    if combined["label"].nunique() != 2:
        raise ValueError("The prepared dataset must contain both Safe and Malicious labels")

    manifest = {
        "sources": list(DATASET_SOURCES),
        "rows_before_deduplication": before,
        "rows_after_deduplication": len(combined),
        "label_mapping": {"0": "Safe", "1": "Malicious"},
        "class_counts": {
            "safe": int((combined["label"] == SAFE_LABEL).sum()),
            "malicious": int((combined["label"] == MALICIOUS_LABEL).sum()),
        },
    }
    return combined.sample(frac=1, random_state=42).reset_index(drop=True), manifest


def split_data(frame: Any, test_size: float, validation_size: float, seed: int) -> Any:
    from datasets import Dataset, DatasetDict
    from sklearn.model_selection import train_test_split

    train_frame, test_frame = train_test_split(
        frame, test_size=test_size, stratify=frame["label"], random_state=seed
    )
    train_frame, validation_frame = train_test_split(
        train_frame,
        test_size=validation_size,
        stratify=train_frame["label"],
        random_state=seed,
    )
    return DatasetDict(
        {
            "train": Dataset.from_pandas(train_frame.reset_index(drop=True), preserve_index=False),
            "validation": Dataset.from_pandas(validation_frame.reset_index(drop=True), preserve_index=False),
            "test": Dataset.from_pandas(test_frame.reset_index(drop=True), preserve_index=False),
        }
    )


def compute_metrics(prediction: Any) -> dict[str, float]:
    import numpy as np
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

    labels = prediction.label_ids
    predictions = np.argmax(prediction.predictions, axis=1)
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
    }


def main() -> None:
    args = parse_args()
    import numpy as np
    if args.max_length <= 0 or not 0 < args.test_size < 1 or not 0 < args.validation_size < 1:
        raise ValueError("max-length must be positive and split sizes must be between 0 and 1")

    set_seed(args.seed)
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    combined, manifest = load_and_prepare_data()
    datasets = split_data(combined, args.test_size, args.validation_size, args.seed)
    manifest["split_counts"] = {name: len(dataset) for name, dataset in datasets.items()}
    manifest["seed"] = args.seed

    if args.skip_training:
        print(json.dumps(manifest, indent=2))
        return

    from transformers import (
        DataCollatorWithPadding,
        DistilBertForSequenceClassification,
        DistilBertTokenizerFast,
        EarlyStoppingCallback,
        Trainer,
        TrainingArguments,
    )

    tokenizer = DistilBertTokenizerFast.from_pretrained(args.model_name)
    model = DistilBertForSequenceClassification.from_pretrained(
        args.model_name,
        num_labels=2,
        id2label={0: "SAFE", 1: "MALICIOUS"},
        label2id={"SAFE": 0, "MALICIOUS": 1},
    )

    def tokenize(batch: dict[str, list[str]]) -> dict[str, Any]:
        return tokenizer(batch["text"], truncation=True, max_length=args.max_length)

    tokenized = datasets.map(tokenize, batched=True)
    tokenized = tokenized.rename_column("label", "labels")
    tokenized = tokenized.remove_columns(["text", "source"])
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)
    import torch

    training_args = TrainingArguments(
        output_dir=str(output_dir / "checkpoints"),
        num_train_epochs=args.epochs,
        learning_rate=args.learning_rate,
        per_device_train_batch_size=args.train_batch_size,
        per_device_eval_batch_size=args.eval_batch_size,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        fp16=torch.cuda.is_available(),
        logging_steps=50,
        report_to="none",
        seed=args.seed,
    )
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["validation"],
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=1)],
    )
    trainer.train()
    metrics = trainer.evaluate(tokenized["test"])
    predictions = trainer.predict(tokenized["test"])
    predicted_labels = np.argmax(predictions.predictions, axis=1)
    from sklearn.metrics import confusion_matrix

    metrics["test_confusion_matrix"] = confusion_matrix(
        predictions.label_ids, predicted_labels, labels=[SAFE_LABEL, MALICIOUS_LABEL]
    ).tolist()
    metrics = {
        key: (float(value) if isinstance(value, (np.floating, float)) else value)
        for key, value in metrics.items()
    }

    model_dir = output_dir / "model"
    trainer.save_model(str(model_dir))
    tokenizer.save_pretrained(str(model_dir))
    manifest.update(
        {
            "model_version": f"distilbert-prompt-injection-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "model_name": args.model_name,
            "max_length": args.max_length,
            "training": {
                "epochs": args.epochs,
                "learning_rate": args.learning_rate,
                "train_batch_size": args.train_batch_size,
                "eval_batch_size": args.eval_batch_size,
            },
            "metrics": metrics,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    (output_dir / "model_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()