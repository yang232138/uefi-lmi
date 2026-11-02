/* Observe only named, mapped RAM regions. No DT writes or hardware commands. */
#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryMapHelperLib.h>
#include <Library/FdtLib.h>
#include "IortProbe.h"

STATIC EFI_GUID mProbeGuid = LMI_IORT_PROBE_GUID;
STATIC LMI_IORT_PROBE mProbe;
STATIC CHAR8 *mNames[] = {"DT BLOB", "XBL DT", "XBL_DT", "Boot FDT"};

STATIC VOID CopyName (CHAR8 *To, CONST CHAR8 *From, UINTN Capacity) {
  UINTN I = 0;
  while (I + 1 < Capacity && From[I] != 0) { To[I] = From[I]; I++; }
  To[I] = 0;
}

STATIC VOID InspectFdt (CONST VOID *Dt, LMI_IORT_REGION *Record) {
  INT32 Node, Length;
  CONST UINT8 *Value;
  CONST CHAR8 *Name;
  Record->ValidFdt++;
  Node = FdtPathOffset (Dt, "/soc/iort");
  Record->IortOffset = Node;
  if (Node >= 0) {
    for (Node = FdtFirstSubnode (Dt, Node); Node >= 0; Node = FdtNextSubnode (Dt, Node)) {
      if (mProbe.NodeCount == LMI_IORT_PROBE_NODES) { mProbe.NodesDropped++; break; }
      Name = FdtGetName (Dt, Node, &Length);
      if (Name != NULL && Length >= 0) {
        CopyName (mProbe.NodeNames[mProbe.NodeCount++], Name, 64);
      }
    }
  }
  Node = FdtPathOffset (Dt, "/soc/iort/NAMEDNODE_UFS_95MEM");
  Record->UfsOffset = Node;
  if (Node < 0) return;
  Value = FdtGetProp (Dt, Node, "CacheCoherency", &Length);
  Record->CacheLength = Length;
  if (Value != NULL && Length == 4) {
    Record->CacheValue = ((UINT32)Value[0] << 24) | ((UINT32)Value[1] << 16) |
                         ((UINT32)Value[2] << 8) | Value[3];
  }
}

EFI_STATUS EFIAPI DiscoverDt (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
  EFI_MEMORY_REGION_DESCRIPTOR Region;
  LMI_IORT_REGION *Record;
  EFI_STATUS Status;
  UINTN I;
  UINT64 Offset, Limit;
  UINT32 Size;
  CONST VOID *Dt;
  (VOID)ImageHandle; (VOID)SystemTable;
  mProbe.Signature = LMI_IORT_PROBE_SIGNATURE;
  mProbe.Version = 1; mProbe.Size = sizeof (mProbe); mProbe.ReadOnly = 1;
  for (I = 0; I < LMI_IORT_PROBE_REGIONS; I++) {
    Record = &mProbe.Regions[I];
    CopyName (Record->Name, mNames[I], sizeof (Record->Name));
    Record->IortOffset = -1; Record->UfsOffset = -1; Record->CacheLength = -1;
    /* A failed lookup leaves its output unspecified: initialize and gate on status. */
    Region.Address = 0; Region.Length = 0;
    Status = LocateMemoryRegionByName (mNames[I], &Region);
    Record->LookupStatus = (UINT64)Status;
    if (EFI_ERROR (Status)) continue;
    Record->Address = Region.Address; Record->Length = Region.Length;
    if (Region.Address == 0 || Region.Length < 40 ||
        Region.Length > MAX_UINT64 - Region.Address ||
        Region.HobOption != AddMem ||
        (Region.ResourceType != EFI_RESOURCE_SYSTEM_MEMORY &&
         Region.ResourceType != EFI_RESOURCE_MEMORY_RESERVED)) {
      Record->Skipped = 1; continue;
    }
    Limit = Region.Length < 0x100000 ? Region.Length : 0x100000;
    for (Offset = 0; Offset + 40 <= Limit; Offset += 4) {
      Dt = (CONST VOID *)(UINTN)(Region.Address + Offset);
      Record->Scanned = Offset + 40;
      if (FdtCheckHeader (Dt) < 0) continue;
      Size = FdtTotalSize (Dt);
      if (Size < 40 || Size > Limit - Offset) continue;
      InspectFdt (Dt, Record);
      /* First complete FDT only, as in the original driver. */
      break;
    }
  }
  /* Success here means the observation table was published, not IOMMU success. */
  return gBS->InstallConfigurationTable (&mProbeGuid, &mProbe);
}
