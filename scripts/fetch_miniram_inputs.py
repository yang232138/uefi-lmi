"""Read a private draft release asset; never publish the reference input files."""
from pathlib import Path
import hashlib, json, os, tarfile, urllib.request
asset=os.environ['INPUT_ASSET_ID']
expected=os.environ['INPUT_ARCHIVE_SHA256']
request=urllib.request.Request('https://api.github.com/repos/yang232138/uefi-lmi/releases/assets/'+asset,
    headers={'Authorization':'Bearer '+os.environ['GITHUB_TOKEN'],'Accept':'application/octet-stream','User-Agent':'LMIPRO-miniram'})
with urllib.request.urlopen(request,timeout=120) as response: data=response.read()
assert hashlib.sha256(data).hexdigest()==expected,'Input archive differs from the locally checked exact assets'
archive=Path('qualified-inputs.tar.gz')
archive.write_bytes(data)
destination=Path('qualified-inputs').resolve()
destination.mkdir(exist_ok=True)
with tarfile.open(archive,'r:gz') as tar:
    for entry in tar.getmembers():
        path=(destination/entry.name).resolve()
        assert destination in path.parents and entry.isfile() and not entry.issym() and not entry.islnk()
    tar.extractall(destination,filter='data')
for path,digest in json.loads((destination/'manifest.json').read_text()).items():
    assert hashlib.sha256((destination/path).read_bytes()).hexdigest()==digest,path
print('PASS: complete pinned reference/firmware/shim inputs restored from an authenticated draft asset')
