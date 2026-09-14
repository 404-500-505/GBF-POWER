#!/usr/bin/env python3
"""Check repository-local Markdown links without following the network."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


LINK = re.compile(r'!?\[[^\]]*\]\((?:<([^>]+)>|([^\s)]+))(?:\s+["\'][^"\']*["\'])?\)')


def markdown_links(text: str):
    fenced = False
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(('```', '~~~')):
            fenced = not fenced
            continue
        if fenced:
            continue
        for match in LINK.finditer(line):
            yield line_number, match.group(1) or match.group(2)


def check(root: Path) -> list[str]:
    root = root.resolve()
    findings: list[str] = []
    for source in sorted(root.rglob('*.md')):
        try:
            text = source.read_text(encoding='utf-8')
        except (OSError, UnicodeError) as exc:
            findings.append(f'{source.relative_to(root)}: cannot read Markdown: {exc}')
            continue
        for line, raw_target in markdown_links(text):
            target = unquote(raw_target.strip())
            if not target or target.startswith(('#', '//')):
                continue
            parsed = urlsplit(target)
            if parsed.scheme in {'http', 'https', 'mailto'}:
                continue
            if parsed.scheme or parsed.netloc:
                findings.append(f'{source.relative_to(root)}:{line}: unsupported link target: {raw_target}')
                continue
            relative = parsed.path
            if not relative:
                continue
            candidate = (source.parent / relative).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                findings.append(f'{source.relative_to(root)}:{line}: link escapes repository: {raw_target}')
                continue
            if not candidate.exists():
                findings.append(f'{source.relative_to(root)}:{line}: missing link target: {raw_target}')
    return findings


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print('usage: check_links.py REPOSITORY', file=sys.stderr)
        return 2
    root = Path(argv[1])
    if not root.is_dir():
        print('repository path is not a directory', file=sys.stderr)
        return 2
    findings = check(root)
    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        return 1
    print('Markdown link check passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
