"""Build a source-only hosting bundle; never include instance data or credentials."""
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent.parent


def build(destination=None):
    destination = Path(destination) if destination else ROOT/'dist/northline-hosting.tar.gz'
    destination.parent.mkdir(parents=True, exist_ok=True)
    roots = ['README.md', '.env.example', 'run.py', 'settings.py', 'backend', 'bot', 'docs',
             'deploy/Caddyfile.example', 'deploy/northline.service', 'deploy/setup-node.sh',
             'deploy/node_control.py', 'deploy/mtproxy', 'deploy/device-probe']
    members = []
    for name in roots:
        path = ROOT/name
        if path.is_file():
            members.append(path)
        else:
            members.extend(item for item in path.rglob('*') if item.is_file() and not item.is_symlink()
                           and '__pycache__' not in item.parts and item.suffix != '.pyc' and item.name != '.DS_Store')
    with tarfile.open(destination, 'w:gz') as archive:
        for path in sorted(members):
            archive.add(path, arcname='northline/'+str(path.relative_to(ROOT)), recursive=False)
    return destination


if __name__ == '__main__':
    path = build()
    print(str(path) + ' (' + str(path.stat().st_size) + ' bytes)')
