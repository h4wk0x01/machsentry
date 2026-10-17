"""Explicit, pinned research acquisition. Stores encrypted ZIP only; never executes."""

from hashlib import sha256
import json
from pathlib import Path
import urllib.request

REVISION = 'de63d2987a933197966b9778fdb746df0968938d'
URL = f'https://raw.githubusercontent.com/objective-see/Malware/{REVISION}/AtomicStealer.zip'
ARCHIVE_SHA256 = '20932399c098674c084f158e2f830e1961bb8ecc7f10e68476458e11a8f64413'
MEMBER_SHA256 = 'ce3c57e6c025911a916a61a716ff32f2699f3e3a84eb0ebbe892a5d4b8fb9c7a'


def main():
    directory = Path(__file__).resolve().parents[1] / 'amostras'
    directory.mkdir(exist_ok=True)
    path = directory / 'AtomicStealer-2023.zip'
    if path.exists():
        data = path.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=30) as response:
            data = response.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024 or sha256(data).hexdigest() != ARCHIVE_SHA256:
        raise SystemExit('Archive size/hash mismatch; nothing installed')
    if not path.exists():
        with path.open('xb') as output:
            output.write(data)
    manifest = {'family_label': 'Atomic Stealer / AMOS', 'label_source': 'Objective-See collection',
                'source_url': URL, 'revision': REVISION, 'collection_commit_date': '2024-01-02',
                'historical_report': 'https://objective-see.org/blog/blog_0x77.html',
                'archive_sha256': ARCHIVE_SHA256, 'member': 'AtomicStealer/Trading View',
                'member_sha256': MEMBER_SHA256, 'password': 'infect3d',
                'executed': False, 'c2_status': 'unknown; not contacted',
                'note': 'Local research input; do not commit or redistribute with the tool'}
    manifest_path = directory / 'provenance.json'
    if manifest_path.exists():
        if json.loads(manifest_path.read_text(encoding='utf-8')) != manifest:
            raise SystemExit('Existing provenance differs; preserved without overwrite')
    else:
        with manifest_path.open('x', encoding='utf-8') as output:
            json.dump(manifest, output, ensure_ascii=False, indent=2)
    print(json.dumps({'archive': str(path), 'manifest': str(manifest_path), 'sha256': ARCHIVE_SHA256}))


if __name__ == '__main__':
    main()
