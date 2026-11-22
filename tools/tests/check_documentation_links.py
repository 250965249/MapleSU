"""Check local Markdown link targets in README.md and docs; never fetch remote links."""
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]


def main():
    paths = [ROOT / 'README.md', *sorted((ROOT / 'docs').rglob('*.md'))]
    checked, missing, inputs = [], [], {}
    for path in paths:
        inputs[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        text = path.read_text(encoding='utf-8-sig')
        text = re.sub(r'(?ms)^```.*?^```\s*$', '', text)
        for match in re.finditer(r'(?<!!)\[[^\]]+\]\(([^)]+)\)', text):
            name = match[1].strip().strip('<>')
            if re.match(r'^[A-Za-z][A-Za-z0-9+.-]*:', name) or name.startswith('#'):
                continue
            name = unquote(name.split('#', 1)[0])
            if not name:
                continue
            record = {'document': path.relative_to(ROOT).as_posix(), 'target': name}
            checked.append(record)
            if not (path.parent / name).exists():
                missing.append(record)
    report = {
        'schemaVersion': 1, 'passed': not missing,
        'scope': 'Local literal Markdown link targets; excludes remote links, heading fragments, '
                 'reference-style links and command execution.',
        'documents': len(paths), 'localLinks': len(checked), 'missing': missing, 'inputs': inputs,
        'testScriptSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    destination = ROOT / '.analysis/documentation-link-validation.json'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key != 'inputs'}, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
