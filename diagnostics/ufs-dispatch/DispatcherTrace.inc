/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Diagnostic state owned by DXE Core. Read only before ExitBootServices.
 * No hardware access, extra driver dispatch or vendor entry calls.
 */
#include "UfsDispatchTrace.h"
#include "SerialBridge.inc"
extern VOID LmiIommuInitialize (VOID);
STATIC BOOLEAN mLmiUfsObserveEnabled;
BOOLEAN LmiUfsObserverEnabled (VOID) { return mLmiUfsObserveEnabled; }

STATIC EFI_GUID mLmiTraceGuid = LMI_TRACE_GUID;
STATIC EFI_GUID mLmiUfsGuid = LMI_UFS_GUID;
STATIC LMI_TRACE_TABLE mLmiTrace = {
  LMI_TRACE_SIGNATURE, LMI_TRACE_VERSION, sizeof (LMI_TRACE_TABLE),
  LMI_TRACE_CAPACITY, 0, 0, LMI_UFS_GUID, {{0,0,0,0}}
};

STATIC VOID
LmiUfsRecord (
  IN EFI_CORE_DRIVER_ENTRY *Entry OPTIONAL,
  IN UINT64 Stage,
  IN EFI_STATUS Status
  )
{
  UINT64 Flags;
  LMI_TRACE_RECORD *Record;

  if ((Entry != NULL) && !CompareGuid (&Entry->FileName, &mLmiUfsGuid)) {
    return;
  }
  if (Entry != NULL) {
    if (Stage == LmiTraceEntryBegin) mLmiUfsObserveEnabled = TRUE;
    if (Stage == LmiTraceEntryEnd) mLmiUfsObserveEnabled = FALSE;
  }
  if (mLmiLog != NULL && Entry != NULL) {
    if (Stage == LmiTraceEntryBegin) mLmiLog->Enabled = 1;
    if (Stage == LmiTraceEntryEnd) mLmiLog->Enabled = 0;
  }
  Flags = 0;
  if (Entry != NULL) {
    Flags = (Entry->Dependent ? BIT0 : 0) |
            (Entry->Scheduled ? BIT1 : 0) |
            (Entry->Initialized ? BIT2 : 0) |
            (Entry->Untrusted ? BIT3 : 0) |
            (Entry->Unrequested ? BIT4 : 0) |
            (Entry->DepexProtocolError ? BIT5 : 0) |
            (Entry->Before ? BIT6 : 0) |
            (Entry->After ? BIT7 : 0) |
            (Entry->IsFvImage ? BIT8 : 0);
  }
  if (mLmiTrace.Count < LMI_TRACE_CAPACITY) {
    Record = &mLmiTrace.Records[mLmiTrace.Count];
    Record->Sequence = (UINT64)mLmiTrace.Count + 1;
    Record->Stage = Stage;
    Record->Status = (UINT64)Status;
    Record->Flags = Flags;
    mLmiTrace.Count++;
  } else if (mLmiTrace.Dropped != MAX_UINT32) {
    mLmiTrace.Dropped++;
  }
  if ((Stage == LmiTraceEntryBegin) || (Stage == LmiTraceEntryEnd)) {
    DEBUG ((DEBUG_ERROR, "LMI-UFS-ORIGINAL stage=%Lu status=%016lx flags=%lx\n",
      Stage, (UINT64)Status, Flags));
  }
}

STATIC VOID
LmiUfsTraceInitialize (VOID)
{
  EFI_STATUS PublishStatus;
  LmiSerialInitialize ();
  LmiIommuInitialize ();
  PublishStatus = CoreInstallConfigurationTable (&mLmiTraceGuid, &mLmiTrace);
  LmiUfsRecord (NULL, LmiTraceInit, PublishStatus);
  DEBUG ((DEBUG_ERROR, "LMI-UFS-TRACE-v1 publish=%r\n", PublishStatus));
}
