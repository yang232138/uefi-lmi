"""Verify actual FV contents and DXE APRIORI ordering before hardware use."""
from pathlib import Path
import contextlib
import hashlib
import io
import json
import shutil
import sys
import uuid
from uefi_firmware.uefi import FirmwareVolume, FirmwareFile, FirmwareFileSystemSection

IORT = '17f55a7f-ddb8-4152-a280-e3984b6eea94'
HAL = '9a00771f-36d4-4dd5-8916-c48ed9b16b86'
UFS = '0d35cd8e-97ea-4f9a-96af-0f0d89f76567'
APRIORI = 'fc510ee7-ffdc-11d4-bd41-0080c73c8881'
UFS_SHA = 'ffeaed467f8251b7e30a45075da84a1c563e2bac7dc4be0f79f0ed49a88b8dc9'
OLD_BOOT = 'c4824ed5539c276454ac510f6c4964fb6bcfcbe64141f3697d49ad2eda80a28d'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def walk(obj):
    yield obj
    for child in getattr(obj, 'objects', []) or []:
        yield from walk(child)

def check(folder):
    fd = (folder / 'SILICIUM_UEFI.fd').read_bytes()
    volume = FirmwareVolume(fd)
    with contextlib.redirect_stdout(io.StringIO()):
        assert volume.process()
    modules = {}
    orders = []
    for f in walk(volume):
        if not isinstance(f, FirmwareFile):
            continue
        guid = str(uuid.UUID(bytes_le=f.guid))
        sections = [s for s in walk(f) if isinstance(s, FirmwareFileSystemSection)]
        pes = [s.data for s in sections if s.type == 0x10]
        if pes:
            modules.setdefault(guid, []).extend(pes)
        if guid == APRIORI:
            for s in sections:
                if s.type == 0x19:
                    assert len(s.data) % 16 == 0
                    orders.append([str(uuid.UUID(bytes_le=s.data[i:i+16])) for i in range(0, len(s.data), 16)])
    assert len(modules.get(IORT, [])) == 1, 'IortDtDxe missing or duplicated'
    assert len(modules.get(HAL, [])) == 1, 'HALIOMMU missing or duplicated'
    assert len(modules.get(UFS, [])) == 1, 'UFSDxe missing or duplicated'
    assert sha(modules[UFS][0]) == UFS_SHA, 'Vendor UFS bytes changed'
    assert len(orders) == 1, 'Expected exactly one DXE APRIORI list'
    order = orders[0]
    assert all(order.count(g) == 1 for g in [IORT, HAL, UFS])
    assert order.index(IORT) < order.index(HAL) < order.index(UFS), 'Invalid DXE APRIORI order'
    assert b'/soc/iort/NAMEDNODE_UFS_95MEM' in modules[IORT][0]
    boot_sha = sha((folder / 'boot.img').read_bytes())
    assert boot_sha != OLD_BOOT, 'Old image substituted'
    return dict(iort_in_fv=True, iort_sha256=sha(modules[IORT][0]),
                iort_apriori_index=order.index(IORT), hal_apriori_index=order.index(HAL),
                ufs_apriori_index=order.index(UFS), apriori_order_verified=True,
                vendor_ufs_sha256=UFS_SHA, boot_sha256=boot_sha, differs_from_previous_boot=True,
                runtime_iort_node_qualified=False, iommu_attach_qualified=False)

if __name__ == '__main__':
    folder = Path(sys.argv[1])
    result = check(folder)
    (folder / 'iort-verification.json').write_text(json.dumps(result, indent=2) + '\n')
    source = Path(__file__).resolve()
    if source != (folder / source.name).resolve():
        shutil.copyfile(source, folder / source.name)
    (folder / 'SHA256SUMS').write_text(''.join(sha(p.read_bytes()) + '  ' + p.name + '\n' for p in sorted(folder.iterdir()) if p.is_file() and p.name != 'SHA256SUMS'))
    print(json.dumps(result, indent=2))
