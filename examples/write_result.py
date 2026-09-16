from pathlib import Path

output = Path("demo-output")
output.mkdir(exist_ok=True)
(output / "result.txt").write_text("verified\n", encoding="utf-8")

