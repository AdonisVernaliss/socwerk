#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".css",
    ".html",
    ".json",
    ".md",
    ".py",
    ".svelte",
    ".svg",
    ".toml",
    ".ts",
    ".yaml",
    ".yml",
}
FORBIDDEN = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "API token assignment": re.compile(
        r"(?i)(api[_-]?key|token|secret)\s*[=:]\s*['\"][A-Za-z0-9_\-]{20,}"
    ),
    "absolute user path": re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+/"),
    "automated-generation marker": re.compile(
        r"(?i)(generated" + r" by an automated tool|machine" + r"-generated)"
    ),
    "unfinished marker": re.compile(
        r"\b(?:T" + r"BD|COMING SO" + r"ON)\b", re.IGNORECASE
    ),
}
MARKDOWN_LINK = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")


def tracked_files() -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        text=True,
    )
    return [ROOT / value for value in output.splitlines() if value]


def main() -> int:
    findings: list[str] = []
    for path in tracked_files():
        if (
            path.name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
            or path.suffix.lower() not in TEXT_SUFFIXES
            or not path.is_file()
        ):
            continue
        relative = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8", errors="replace")
        for label, pattern in FORBIDDEN.items():
            if pattern.search(text):
                findings.append(f"{relative}: {label}")
        if path.suffix.lower() == ".md":
            for target in MARKDOWN_LINK.findall(text):
                clean_target = target.strip("<>").split("#", 1)[0]
                if (
                    not clean_target
                    or "://" in clean_target
                    or clean_target.startswith("mailto:")
                ):
                    continue
                linked_path = (
                    path.parent / urllib.parse.unquote(clean_target)
                ).resolve()
                if not linked_path.is_relative_to(ROOT) or not linked_path.exists():
                    findings.append(f"{relative}: broken local link {target}")
    if findings:
        print("Repository sanity check failed:")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print("Repository sanity check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
