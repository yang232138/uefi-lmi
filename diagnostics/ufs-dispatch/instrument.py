"""Instrument normal DXE dispatch only; fail closed on source drift."""
from pathlib import Path
import argparse, hashlib, json, shutil

SOURCE_SHA = '24f50beeab071c52acbcbdabf8b282a2edcd7963a8744bb586950f607cc0b9bf'
SHIM_SOURCE_SHA = '5378fa6d0273b332e5e6e178c1b9c5793283e5b1f67cf13ce4e2628c0144c209'

def transform_shim(text):
    for old,new in [
        ('#include "PlatformPei.h"', '#include "PlatformPei.h"\n#include "SerialCapture.inc"'),
        ('  SerialPortWrite,', '  LmiSerialWrite,'),
        ('{"SerialPort Lib",  &SioLib}', '{"SerialPort Lib",  &SioLib},\n  {LMI_LOG_LIB_NAME, &mLmiSerialLog}')]:
        assert text.count(old)==1,repr(old)
        text=text.replace(old,new)
    return text

def transform(text):
    def edit(old, new):
        nonlocal text
        assert text.count(old) == 1, repr(old)
        text = text.replace(old, new)
    edit('#include "DxeMain.h"', '#include "DxeMain.h"\n#include "DispatcherTrace.inc"')
    edit('  BOOLEAN                ReadyToRun;',
         '  BOOLEAN                ReadyToRun;\n  BOOLEAN                LmiSchedulable;')
    edit('        Status = CoreLoadImage (',
         '        LmiUfsRecord (DriverEntry, LmiTraceLoadBegin, EFI_NOT_READY);\n        Status = CoreLoadImage (')
    edit('                   &DriverEntry->ImageHandle\n                   );',
         '                   &DriverEntry->ImageHandle\n                   );\n        LmiUfsRecord (DriverEntry, LmiTraceLoadEnd, Status);')
    edit('        Status = CoreStartImage (DriverEntry->ImageHandle, NULL, NULL);',
         '        LmiUfsRecord (DriverEntry, LmiTraceEntryBegin, EFI_NOT_READY);\n'
         '        Status = CoreStartImage (DriverEntry->ImageHandle, NULL, NULL);\n'
         '        LmiUfsRecord (DriverEntry, LmiTraceEntryEnd, Status);')
    edit('        if (CoreIsSchedulable (DriverEntry)) {',
         '        LmiSchedulable = CoreIsSchedulable (DriverEntry);\n'
         '        LmiUfsRecord (DriverEntry, LmiTraceDependency, LmiSchedulable ? EFI_SUCCESS : EFI_NOT_READY);\n'
         '        if (LmiSchedulable) {')
    edit('  gDispatcherRunning = FALSE;\n\n  PERF_FUNCTION_END ();',
         '  gDispatcherRunning = FALSE;\n\n'
         '  LmiUfsRecord (NULL, LmiTraceDispatchEnd, ReturnStatus);\n\n  PERF_FUNCTION_END ();')
    edit('  InsertTailList (&mScheduledQueue, &InsertedDriverEntry->ScheduledLink);\n\n  CoreReleaseDispatcherLock ();',
         '  InsertTailList (&mScheduledQueue, &InsertedDriverEntry->ScheduledLink);\n\n  CoreReleaseDispatcherLock ();\n'
         '  LmiUfsRecord (InsertedDriverEntry, LmiTraceScheduled, EFI_SUCCESS);')
    edit('  InsertTailList (&mDiscoveredList, &DriverEntry->Link);\n\n  CoreReleaseDispatcherLock ();',
         '  InsertTailList (&mDiscoveredList, &DriverEntry->Link);\n\n  CoreReleaseDispatcherLock ();\n'
         '  LmiUfsRecord (DriverEntry, LmiTraceDiscovered, EFI_SUCCESS);')
    edit('          DEBUG ((DEBUG_DISPATCH, "  RESULT = TRUE (Apriori)\\n"));',
         '          DEBUG ((DEBUG_DISPATCH, "  RESULT = TRUE (Apriori)\\n"));\n'
         '          LmiUfsRecord (DriverEntry, LmiTraceApriori, EFI_SUCCESS);')
    edit('CoreInitializeDispatcher (\n  VOID\n  )\n{\n  PERF_FUNCTION_BEGIN ();',
         'CoreInitializeDispatcher (\n  VOID\n  )\n{\n  PERF_FUNCTION_BEGIN ();\n\n  LmiUfsTraceInitialize ();')
    return text

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--edk2', type=Path, required=True)
    ap.add_argument('--uefi', type=Path, required=True)
    args=ap.parse_args(); folder=Path(__file__).resolve().parent
    path=args.edk2/'MdeModulePkg/Core/Dxe/Dispatcher/Dispatcher.c'
    raw=path.read_bytes(); normalized=raw.replace(b'\r\n', b'\n')
    assert hashlib.sha256(normalized).hexdigest()==SOURCE_SHA, 'Pinned dispatcher mismatch'
    changed=transform(normalized.decode())
    path.write_text(changed, encoding='utf-8', newline='\n')
    for name in ('DispatcherTrace.inc', 'UfsDispatchTrace.h', 'SerialBridge.inc', 'UfsSerialLog.h'):
        shutil.copyfile(folder/name, path.parent/name)
    shim=args.uefi/'Silicon/Qualcomm/QcomPkg/Library/PlatformPeiLib/ShimLoader.c'
    before=shim.read_bytes().replace(b'\r\n',b'\n')
    assert hashlib.sha256(before).hexdigest()==SHIM_SOURCE_SHA,'Pinned ShimLoader mismatch'
    after=transform_shim(before.decode())
    shim.write_text(after,encoding='utf-8',newline='\n')
    for name in ('SerialCapture.inc','UfsSerialLog.h'):
        shutil.copyfile(folder/name,shim.parent/name)
    print(json.dumps({'dispatcher_before':SOURCE_SHA,'dispatcher_after':hashlib.sha256(changed.encode()).hexdigest(),
                      'shim_before':SHIM_SOURCE_SHA,'shim_after':hashlib.sha256(after.encode()).hexdigest(),
                      'extra_driver_starts':False,'vendor_binary_changes':False}))

if __name__=='__main__': main()
