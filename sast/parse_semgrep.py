import json
import os

# summarise the Semgrep JSON output into a short readable list
# usage: python parse_semgrep.py   (run from the sast/ folder)

results = []
here = os.path.dirname(os.path.abspath(__file__))
for fname in ['semgrep-routes.json', 'semgrep-lib.json']:
    fpath = os.path.join(here, fname)
    if os.path.exists(fpath):
        with open(fpath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for r in data.get('results', []):
            path = r['path'].replace('\\', '/')
            line = r['start']['line']
            sev = r['extra']['severity']
            check = r['check_id'].split('.')[-1]
            cwes = r['extra']['metadata'].get('cwe', ['N/A'])
            cwe_str = cwes[0] if cwes else 'N/A'
            msg = r['extra']['message'][:100]
            results.append((sev, check, path, line, cwe_str, msg))

print(f"Total findings: {len(results)}")
print()
for sev, check, path, line, cwe, msg in results:
    print(f"[{sev}] {check}")
    print(f"  File: {path}:{line}")
    print(f"  CWE: {cwe}")
    print(f"  Msg: {msg}...")
    print()
