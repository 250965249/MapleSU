"""Find config values used only in an unreferenced external array declaration.

This deliberately narrow rule does not cover a struct, enum, preprocessor
condition, inline function, sizeof use, initializer or imported symbol.
"""
import re


def declaration_configs(sources, values, imports):
    text = '\n'.join(re.sub(r'/\*.*?\*/|//[^\n]*', '', source, flags=re.S)
                     for source in sources.values())
    result = []
    for key, value in values.items():
        if not re.fullmatch(r'[1-9][0-9]*', value):
            continue
        hits = list(re.finditer(r'\b' + re.escape(key) + r'\b', text))
        if len(hits) != 1:
            continue
        # An extern array bound affects no object or code if the symbol has no
        # use anywhere in the full translation-unit dependency set.
        declaration = re.compile(r'\bextern\s+(?:const\s+)?(?:u64|unsigned\s+long(?:\s+long)?)\s+'
            r'([A-Za-z_]\w*)\s*\[\s*' + re.escape(key) + r'\s*/\s*sizeof\s*\(\s*'
            r'(?:u64|unsigned\s+long(?:\s+long)?)\s*\)\s*\]\s*;')
        match = next((m for m in declaration.finditer(text) if m.start() <= hits[0].start() < m.end()), None)
        if match and match.group(1) not in imports:
            remainder = text[:match.start()] + text[match.end():]
            # Taking element zero's address does not consume the array bound.
            # Any other use (including sizeof/object-size/iteration) is rejected.
            remainder = re.sub(r'\breturn\s+&\s*' + match.group(1) + r'\s*\[\s*0\s*\]\s*;', '', remainder)
            if not re.search(r'\b' + match.group(1) + r'\b', remainder):
                result.append(key)
    return sorted(result)


if __name__ == '__main__':
    import hashlib
    import json
    from pathlib import Path
    import sys
    directory = Path(sys.argv[1])
    kernel = directory.name
    commands = [directory / ('.' + Path(name).name + '.cmd') for name in
                (directory / 'maplesu_policy_view.mod').read_text().splitlines()]
    paths = set()
    for command in commands:
        for line in command.read_text().splitlines():
            entry = line.strip().removesuffix('\\').strip()
            if not entry or any(c in entry for c in (' ', ':', '$', '=')):
                continue
            if entry.startswith('/opt/ddk/src/') or entry.startswith('/output/'):
                paths.add(Path(entry))
            elif entry.startswith(('include/', 'arch/')) and not entry.startswith('include/config/'):
                paths.add(Path('/opt/ddk/kdir') / kernel / entry)
    paths.update(directory.glob('*.c')); paths.update(directory.glob('*.S'))
    sources = {str(path): path.read_text() for path in sorted(paths) if path.is_file()}
    if any(not path.is_file() for path in paths):
        raise ValueError('Incomplete declaration dependency set: ' + str([str(p) for p in paths if not p.is_file()]))
    contract = json.loads((directory / 'kernel-compatibility.json').read_text())
    values = contract['config']
    # Symbol use checking includes all imports, including ones outside DATA.
    # Read undefined symbols with the DDK's tool, not a user-supplied import list.
    import subprocess
    symbols = subprocess.check_output(['llvm-nm', '-u', directory/'policy-view.so'], text=True)
    imports = [line.split()[-1] for line in symbols.splitlines() if line.split()]
    consumed = {name: text for name, text in sources.items() if not name.endswith('/include/generated/autoconf.h')}
    result = dict(schemaVersion=1, configs=declaration_configs(consumed, values, imports),
        generatorSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        sourceSha256={name: hashlib.sha256(source.encode()).hexdigest() for name, source in sorted(sources.items())},
        inputSha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in
            [*commands, directory/'policy-view.so', directory/'compiled-layout.json', directory/'target.config']})
    (directory / 'config-declarations.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(configs=result['configs'], inspectedSources=len(sources))))
