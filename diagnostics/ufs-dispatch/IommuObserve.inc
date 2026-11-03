/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * ABI derived from the pinned, unchanged SM8250 HALIOMMU/UFS binaries.
 * Only the original UFS entry receives this observer. All calls forward once.
 * No allocation, MMIO, protocol installation or additional vendor calls.
 */
#include "IommuObserve.h"
extern BOOLEAN LmiUfsObserverEnabled (VOID);
typedef UINT32 (EFIAPI *LMI_CREATE)(VOID **Domain);
typedef UINT32 (EFIAPI *LMI_CONFIGURE)(VOID *Domain, UINT32 Mode);
typedef UINT32 (EFIAPI *LMI_ATTACH)(VOID *Domain, CHAR8 *Name, UINT32 Arid, UINT32 Flags);
typedef struct {
  LMI_CREATE Create;
  VOID *Delete;
  LMI_ATTACH Attach;
  VOID *Detach, *SetConfig, *Slot5, *Slot6, *Slot7;
  LMI_CONFIGURE Configure;
} LMI_FUNCTIONS;
typedef VOID (EFIAPI *LMI_GET_FUNCTIONS)(LMI_FUNCTIONS **Functions);
typedef struct { UINT64 Revision; LMI_GET_FUNCTIONS GetFunctions; VOID *Slot2; } LMI_PROTOCOL;
STATIC EFI_GUID mLmiHalGuid = {0x54b6d3b4,0x5d33,0x4f91,{0x86,0x00,0x6c,0x41,0xd5,0xde,0xb1,0x9a}};
STATIC EFI_GUID mLmiIommuGuid = LMI_IOMMU_GUID;
STATIC LMI_IOMMU_TABLE mLmiIommu = {
  .Signature=LMI_IOMMU_SIGNATURE, .Version=1, .Size=sizeof(LMI_IOMMU_TABLE)
};
STATIC LMI_PROTOCOL *mLmiOriginalProtocol;
STATIC LMI_PROTOCOL mLmiProxyProtocol;
STATIC LMI_FUNCTIONS *mLmiOriginalFunctions;
STATIC LMI_FUNCTIONS mLmiProxyFunctions;
STATIC LMI_IOMMU_RECORD *
LmiIommuBegin (UINT32 Kind, VOID *Domain, UINT64 Argument, UINT32 Arid, UINT32 Flags)
{
  LMI_IOMMU_RECORD *R;
  if (!LmiUfsObserverEnabled ()) return NULL;
  if (mLmiIommu.Count >= LMI_IOMMU_CAPACITY) {
    if (mLmiIommu.Dropped != MAX_UINT32) mLmiIommu.Dropped++;
    return NULL;
  }
  R=&mLmiIommu.Records[mLmiIommu.Count++];
  R->Kind=Kind; R->Domain=(UINT64)(UINTN)Domain; R->Argument=Argument;
  R->Arid=Arid; R->Flags=Flags;
  return R;
}
STATIC VOID LmiIommuEnd (LMI_IOMMU_RECORD *R, UINT32 Result)
{
  if (R != NULL) { R->ReturnCode=Result; R->Completed=1; }
}
STATIC UINT32 EFIAPI LmiIommuCreate (VOID **Domain)
{
  LMI_IOMMU_RECORD *R=LmiIommuBegin(1,NULL,(UINT64)(UINTN)Domain,0,0);
  UINT32 Result=mLmiOriginalFunctions->Create(Domain);
  if (R != NULL && Result == 0 && Domain != NULL) R->Domain=(UINT64)(UINTN)*Domain;
  LmiIommuEnd(R,Result); return Result;
}
STATIC UINT32 EFIAPI LmiIommuConfigure (VOID *Domain, UINT32 Mode)
{
  LMI_IOMMU_RECORD *R=LmiIommuBegin(2,Domain,Mode,0,0);
  UINT32 Result=mLmiOriginalFunctions->Configure(Domain,Mode);
  LmiIommuEnd(R,Result); return Result;
}
STATIC UINT32 EFIAPI LmiIommuAttach (VOID *Domain, CHAR8 *Name, UINT32 Arid, UINT32 Flags)
{
  LMI_IOMMU_RECORD *R=LmiIommuBegin(3,Domain,(UINT64)(UINTN)Name,Arid,Flags);
  UINT32 Result=mLmiOriginalFunctions->Attach(Domain,Name,Arid,Flags);
  LmiIommuEnd(R,Result); return Result;
}
STATIC VOID EFIAPI LmiIommuGetFunctions (LMI_FUNCTIONS **Functions)
{
  LMI_FUNCTIONS *Original;
  mLmiOriginalProtocol->GetFunctions(Functions);
  if (!LmiUfsObserverEnabled () || Functions == NULL || *Functions == NULL) return;
  Original=*Functions;
  if (Original->Create == NULL || Original->Configure == NULL || Original->Attach == NULL) return;
  if (mLmiOriginalFunctions != NULL && mLmiOriginalFunctions != Original) return;
  mLmiOriginalFunctions=Original;
  CopyMem(&mLmiProxyFunctions,Original,sizeof(mLmiProxyFunctions));
  mLmiProxyFunctions.Create=LmiIommuCreate;
  mLmiProxyFunctions.Configure=LmiIommuConfigure;
  mLmiProxyFunctions.Attach=LmiIommuAttach;
  mLmiIommu.Functions=(UINT64)(UINTN)Original;
  mLmiIommu.Wrapped++;
  *Functions=&mLmiProxyFunctions;
}
STATIC VOID LmiIommuObserveLocated (EFI_GUID *Protocol, VOID **Interface)
{
  LMI_PROTOCOL *Original;
  if (!LmiUfsObserverEnabled () || !CompareGuid(Protocol,&mLmiHalGuid) ||
      Interface == NULL || *Interface == NULL) return;
  mLmiIommu.Located++;
  Original=*Interface;
  if (Original->Revision != 1 || Original->GetFunctions == NULL) return;
  if (mLmiOriginalProtocol != NULL && mLmiOriginalProtocol != Original) return;
  mLmiOriginalProtocol=Original;
  CopyMem(&mLmiProxyProtocol,Original,sizeof(mLmiProxyProtocol));
  mLmiProxyProtocol.GetFunctions=LmiIommuGetFunctions;
  mLmiIommu.Protocol=(UINT64)(UINTN)Original;
  *Interface=&mLmiProxyProtocol;
}
VOID LmiIommuInitialize (VOID)
{
  CoreInstallConfigurationTable(&mLmiIommuGuid,&mLmiIommu);
  DEBUG((DEBUG_ERROR,"LMI-IOMMU-ORIGINAL-CALL-v1\n"));
}
