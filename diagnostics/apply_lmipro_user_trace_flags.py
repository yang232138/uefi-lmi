"""Explicit per-file diagnostic flags; use the existing reference/final mode stamp."""
from pathlib import Path
import hashlib,json,sys
root=Path(sys.argv[1]);path=root/'scripts/build-xnu-4k-baseline.sh';before=path.read_text();text=before
assert 'LMIPRO_USER_TRACE' not in text
anchor='if [ "$(cat "$SHENG_PMGR_STAMP" 2>/dev/null || echo 0)" != "$SHENG_PMGR" ]; then\n  rm -f "$ROOT/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/bsd_init.o"\n'
assert text.count(anchor)==1
text=text.replace(anchor,anchor+'''  rm -f "$ROOT/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/osfmk/DEVELOPMENT/sleh.o"
  rm -f "$ROOT/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/systemcalls.o"
  rm -f "$ROOT/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/bsd/DEVELOPMENT/kern_descrip.o"
''')
line=next(s for s in text.splitlines() if s.startswith('EXTRA_MAKE_ARGS+=("bsd_init.o_CFLAGS_ADD='))
assert text.count(line)==1
text=text.replace(line,line+'\nEXTRA_MAKE_ARGS+=("sleh.o_CFLAGS_ADD=-DLMIPRO_USER_TRACE=$SHENG_PMGR" "systemcalls.o_CFLAGS_ADD=-DLMIPRO_USER_TRACE=$SHENG_PMGR" "kern_descrip.o_CFLAGS_ADD=-DLMIPRO_USER_TRACE=$SHENG_PMGR")')
path.write_text(text,encoding='utf-8',newline='\n')
out=root/'build/lmipro-user-trace-flags.json';out.parent.mkdir(parents=True,exist_ok=True)
out.write_text(json.dumps(dict(base_sha256=hashlib.sha256(before.encode()).hexdigest(),
    instrumented_sha256=hashlib.sha256(text.encode()).hexdigest(),
    target_files=['osfmk/arm64/sleh.c','bsd/dev/arm/systemcalls.c','bsd/kern/kern_descrip.c'],
    reference_mode=0,final_mode=1,uses_existing_mode_stamp=True),indent=2)+'\n')
print('PASS: trace flags explicit on three source files; mode changes invalidate all three objects')
