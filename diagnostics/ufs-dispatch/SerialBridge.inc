/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Read the existing documented Shim HOB and loader interface. Publish only
 * our named RAM buffer. No IOMMU methods, disk calls or vendor image edits.
 */
#include "UfsSerialLog.h"
typedef struct {
  UINT32 LoaderVersion;
  EFI_STATUS (*InstallLib)(CHAR8 *,UINT32,VOID *);
  EFI_STATUS (*LoadLib)(CHAR8 *,UINT32,VOID **);
} LMI_SHIM_LOADER;
STATIC EFI_GUID mLmiShimHobGuid = {0xBEDAEABC,0x5E70,0x4D66,{0x97,0x33,0x21,0x3D,0x07,0x2B,0x9D,0x04}};
STATIC EFI_GUID mLmiLogGuid = LMI_LOG_GUID;
STATIC LMI_SERIAL_LOG *mLmiLog;
STATIC VOID
LmiSerialInitialize (VOID)
{
  VOID *Hob;
  LMI_SHIM_LOADER *Loader;
  LMI_SERIAL_LOG *Log = NULL;
  Hob = GetFirstGuidHob (&mLmiShimHobGuid);
  if (Hob == NULL || GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (UINTN)) return;
  Loader = (LMI_SHIM_LOADER *)(*(UINTN *)GET_GUID_HOB_DATA (Hob));
  if (Loader == NULL || Loader->LoadLib == NULL) return;
  if (EFI_ERROR (Loader->LoadLib (LMI_LOG_LIB_NAME,0,(VOID **)&Log))) return;
  if (Log == NULL || Log->Signature != LMI_LOG_SIGNATURE || Log->Version != 1 ||
      Log->Size != sizeof (*Log) || Log->Capacity != LMI_LOG_CAPACITY ||
      Log->Count > Log->Capacity) return;
  mLmiLog = Log;
  CoreInstallConfigurationTable (&mLmiLogGuid,Log);
}
