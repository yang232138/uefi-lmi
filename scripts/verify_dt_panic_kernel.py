"""Verify that the existing upstream DT-panic feature reached the new kernel."""
from pathlib import Path
import argparse, hashlib, json, shutil, subprocess

ap = argparse.ArgumentParser()
ap.add_argument('--work', type=Path, required=True)
ap.add_argument('--out', type=Path, required=True)
a = ap.parse_args()
a.out.mkdir(parents=True, exist_ok=True)
tree = a.work/'tree'
config = (a.work/'.config').read_text()
assert 'CONFIG_XNU_DT_PANIC_REGION=y' in config
stamp = tree/'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/.dt-panic-region-mode'
assert stamp.read_text().strip() == '1'
source = (tree/'.cache/xnu-work/pexpert/arm/pe_init.c').read_text()
assert '#if defined(PLATFORM_PANIC_LOG_PADDR) && !(defined(XNU_DT_PANIC_REGION) && XNU_DT_PANIC_REGION)' in source
assert 'size != 2 * sizeof(*reg_prop)' in source
assert 'reg_prop[0] > UINTPTR_MAX - reg_prop[1]' in source
assert 'panic_region_length[0] > reg_prop[1]' in source
kernel = a.work/'kernel/kernel.macho'
nm = shutil.which('llvm-nm')
objdump = shutil.which('llvm-objdump')
assert nm and objdump
lines = subprocess.run([nm, '-n', str(kernel)], check=True, text=True, capture_output=True).stdout.splitlines()
symbols = {}
for line in lines:
    parts = line.split()
    if len(parts) == 3:
        symbols.setdefault(int(parts[0], 16), parts[2])
starts = sorted(symbols)
assembly = []
for name in ['_PE_create_console', '_check_for_panic_log']:
    addresses = [n for n in starts if symbols[n] == name]
    if not addresses:
        assert name != '_PE_create_console'
        continue
    start = addresses[0]
    end = next(n for n in starts if n > start)
    text = subprocess.run([objdump, '-d', f'--start-address={start:#x}', f'--stop-address={end:#x}', str(kernel)],
                          check=True, text=True, capture_output=True).stdout
    assembly.append(text)
compiled = '\n'.join(assembly)
assert '_SecureDTLookupEntry' in compiled and '_SecureDTGetProperty' in compiled, 'Compiled DT path missing'
assert '#0x3c0f' not in compiled.lower(), 'Fixed BCM panic address still present'
(a.out/'panic-region-disassembly.txt').write_text(compiled)
shutil.copyfile(kernel, a.out/'kernel-original.macho')
shutil.copyfile(a.work/'.config', a.out/'kernel.config')
shutil.copyfile(stamp, a.out/'dt-panic-region-mode.txt')
report = dict(unixnu_revision='ee472385743ebd16941ab14892dcb9d02e219d15',
    device_revision='46df25155308279c56ec5098ea7d36ee7e43a7c3',
    config='CONFIG_XNU_DT_PANIC_REGION=y', compiled_mode=1,
    applied_upstream_patch='native-dt-panic-region.patch',
    patched_source_sha256=hashlib.sha256(source.encode()).hexdigest(),
    kernel_sha256=hashlib.sha256(kernel.read_bytes()).hexdigest(), kernel_bytes=kernel.stat().st_size,
    compiled_dt_lookup_present=True, compiled_dt_property_lookup_present=True,
    fixed_bcm_panic_address_in_inspected_functions=False,
    new_hardware_addresses_added=False, root_cause_proven=False, hardware_test='pending')
(a.out/'kernel-build-proof.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
