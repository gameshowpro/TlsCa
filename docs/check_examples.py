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

from render_https_guide import PAGE_HEADINGS, render, render_file  # noqa: E402

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
            if "Install anyway" not in text or "download notification" not in text:
                failures.append(f"{example.name}: Android Settings installation steps are missing.")
            if example.name == "soundling.md":
                if "Continue over HTTP" in text:
                    failures.append("soundling.md: guide offers the disabled HTTP escape.")
                if "Continue on this address" not in text or "HTTPS IP addresses" not in text:
                    failures.append("soundling.md: guide does not explain the HTTPS IP escape.")
            if example.name == "triggergate.yaml":
                if "Continue over HTTP" not in text:
                    failures.append("triggergate.yaml: guide omits the HTTP escape.")
                if "On Windows service and Uno" not in text:
                    failures.append("triggergate.yaml: guide must not promise the HTTPS escape for ESP32 firmware.")
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
        no_escape = render({
            "product": "Test",
            "http_port": 8080,
            "https_port": 8443,
            "name_pattern": "<host>-test.local",
            "name_example": "desk-test.local",
            "allow_http_fallback": False,
            "allow_https_fallback": False,
        })
        if "Continue over HTTP" in no_escape or "Continue on this address" in no_escape:
            failures.append("Guide with both escapes disabled still describes an escape.")
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
