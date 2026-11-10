import re
from pathlib import Path

from app.detector import HeuristicDetector


def demo_prompts(name: str) -> list[str]:
    source = (Path(__file__).parents[2] / "client" / "src" / "lib" / "demo-prompts.ts").read_text()
    body = source.split(f"export const {name} = [", 1)[1].split("];", 1)[0]
    return re.findall(r'"((?:\\.|[^"\\])*)"', body)


def test_demo_safe_prompts_are_not_blocked() -> None:
    detector = HeuristicDetector()

    results = [detector.detect(prompt) for prompt in demo_prompts("SAFE_PROMPTS_POOL")]

    assert all(result.classification == "Safe" for result in results)


def test_demo_injection_prompts_are_blocked() -> None:
    detector = HeuristicDetector()

    results = [detector.detect(prompt) for prompt in demo_prompts("INJECTION_PROMPTS_POOL")]

    assert all(result.classification == "Malicious" for result in results)
