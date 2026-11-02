"""Instrument normal DXE dispatch only; fail closed on source drift."""
from pathlib import Path
import argparse, hashlib, json, shutil

SOURCE_SHA = '1008348b1e53ac656f613a55aebbf33d162db133eaedc506dedde1bf96a9dba8'

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
    args=ap.parse_args(); folder=Path(__file__).resolve().parent
    path=args.edk2/'MdeModulePkg/Core/Dxe/Dispatcher/Dispatcher.c'
    raw=path.read_bytes(); normalized=raw.replace(b'\r\n', b'\n')
    assert hashlib.sha256(normalized).hexdigest()==SOURCE_SHA, 'Pinned dispatcher mismatch'
    changed=transform(normalized.decode())
    path.write_text(changed, encoding='utf-8', newline='\n')
    for name in ('DispatcherTrace.inc', 'UfsDispatchTrace.h'):
        shutil.copyfile(folder/name, path.parent/name)
    print(json.dumps({'dispatcher_before':SOURCE_SHA,'dispatcher_after':hashlib.sha256(changed.encode()).hexdigest(),
                      'extra_driver_starts':False,'vendor_binary_changes':False}))

if __name__=='__main__': main()
