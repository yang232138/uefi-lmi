/** @file
  Keep the UFS device awake across ExitBootServices.

  The vendor UFSDxe leaves the device in a low-power state and XNU has no way
  to bring the UniPro link back up on this board (UIC DME_HIBERNATE_EXIT and
  DME_LINK_STARTUP both leave the active lane count at zero). This driver:

    1. reads one block through the vendor BlockIo protocol, which keeps the
       device in its ACTIVE power state;
    2. clears the UFSHCI auto-hibernate idle timer so the device does not drop
       back into hibernate before the OS takes the controller over.

  It never submits a SCSI command of its own and never writes to storage.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/BlockIo.h>

#define UFS_HC_BASE              0x01D84000ULL
#define UFS_REG_AUTO_HIBERNATE   0x18
#define UFS_REG_INTERRUPT_ENABLE 0x24

STATIC
volatile UINT32 *
UfsReg (
  IN UINT32 Offset
  )
{
  return (volatile UINT32 *)(UINTN)(UFS_HC_BASE + Offset);
}

EFI_STATUS
EFIAPI
UfsKeepAliveEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS           Status;
  EFI_HANDLE           *Handles;
  UINTN                Count;
  UINTN                Index;
  BOOLEAN              ReadOk;

  Handles = NULL;
  Count   = 0;
  ReadOk  = FALSE;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  &Count,
                  &Handles
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "UfsKeepAlive: no BlockIo (%r)\n", Status));
    return EFI_SUCCESS;
  }

  for (Index = 0; Index < Count; Index++) {
    EFI_BLOCK_IO_PROTOCOL  *BlockIo;
    UINT8                  *Buffer;

    BlockIo = NULL;
    Status  = gBS->HandleProtocol (
                     Handles[Index],
                     &gEfiBlockIoProtocolGuid,
                     (VOID **)&BlockIo
                     );
    if (EFI_ERROR (Status) || (BlockIo == NULL) || (BlockIo->Media == NULL)) {
      continue;
    }
    if (!BlockIo->Media->MediaPresent || (BlockIo->Media->BlockSize == 0)) {
      continue;
    }

    Buffer = AllocatePool (BlockIo->Media->BlockSize);
    if (Buffer == NULL) {
      continue;
    }
    Status = BlockIo->ReadBlocks (
                        BlockIo,
                        BlockIo->Media->MediaId,
                        0,
                        BlockIo->Media->BlockSize,
                        Buffer
                        );
    FreePool (Buffer);
    DEBUG ((
      DEBUG_INFO,
      "UfsKeepAlive: BlockIo[%u] LBA0 -> %r\n",
      (UINT32)Index,
      Status
      ));
    if (!EFI_ERROR (Status)) {
      ReadOk = TRUE;
    }
  }
  FreePool (Handles);

  *UfsReg (UFS_REG_INTERRUPT_ENABLE)   = 0;
  *UfsReg (UFS_REG_AUTO_HIBERNATE)     = 0;
  DEBUG ((
    DEBUG_INFO,
    "UfsKeepAlive: read=%u auto-hibernate timer cleared\n",
    ReadOk ? 1U : 0U
    ));

  return EFI_SUCCESS;
}
