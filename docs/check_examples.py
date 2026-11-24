"""Check the HTTPS user guide: render every example and build the results with MkDocs in strict mode.

Run by CI and before changing https-guide.md or render_https_guide.py:
    python docs/check_examples.py

Fails when an example does not render, when template syntax is left in the output, when a section of an application
page is lost in the merge, or when MkDocs reports a problem (for example a link to an anchor that does not exist).
Needs MkDocs with the Material theme.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

DOCS = Path(__file__).resolve().parent
sys.path.insert(0, str(DOCS))
sys.dont_write_bytecode = True

from render_https_guide import PAGE_HEADINGS, render_file  # noqa: E402

MKDOCS = """site_name: HTTPS guide check
theme:
  name: material
  font: false
markdown_extensions:
  - tables
  - toc:
      permalink: true
validation:
  links:
    anchors: warn
"""


def main():
    failures = []
    with tempfile.TemporaryDirectory() as folder:
        site = Path(folder)
        (site / "docs").mkdir()
        (site / "mkdocs.yml").write_text(MKDOCS, encoding="utf-8")
        examples = sorted(p for p in (DOCS / "examples").iterdir() if p.suffix.lower() in (".md", ".yaml", ".yml", ".json"))
        if not examples:
            failures.append("There are no examples to check.")
        for index, example in enumerate(examples):
            text = render_file(example)
            if "{{" in text or "{%" in text or "{#" in text:
                failures.append(f"{example.name}: template syntax is left in the rendered page.")
            if "repository-only" in text:
                failures.append(f"{example.name}: a repository-only note is left in the rendered page.")
            if example.suffix.lower() == ".md":
                # Every line of the application's own sections must survive the merge.
                body = example.read_text(encoding="utf-8").split("\n---", 1)[1]
                body = body.split("<!-- /repository-only -->")[-1]
                for line in body.splitlines():
                    line = line.strip()
                    is_heading = line.startswith("# ") or line.lstrip("# ") in PAGE_HEADINGS
                    if line and not is_heading and line not in text:
                        failures.append(f"{example.name}: this line is missing from the merged page: {line}")
            name = "index.md" if index == 0 else example.stem + ".md"
            (site / "docs" / name).write_text(text, encoding="utf-8", newline="\n")
        result = subprocess.run(
            [sys.executable, "-m", "mkdocs", "build", "--strict", "--quiet", "--site-dir", str(site / "out")],
            cwd=site, capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            failures.append("MkDocs failed:\n" + result.stdout + result.stderr)
    for failure in failures:
        print(f"check_examples: {failure}", file=sys.stderr)
    if not failures:
        print(f"check_examples: {len(examples)} examples rendered and built.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
