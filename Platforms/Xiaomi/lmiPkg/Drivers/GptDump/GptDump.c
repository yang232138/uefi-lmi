/** @file
  Print the GPT of every block device the firmware can see.

  Bring-up aid for reading the handset's real partition geometry (the LS-1
  build has no adb, no root and fastboot does not expose partition offsets).
  The output is held on screen for a few seconds so it can be photographed;
  this driver is meant to be removed once the geometry is recorded.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/BlockIo.h>

#pragma pack(1)
typedef struct {
  UINT64    Signature;
  UINT32    Revision;
  UINT32    HeaderSize;
  UINT32    HeaderCrc;
  UINT32    Reserved;
  UINT64    MyLba;
  UINT64    AlternateLba;
  UINT64    FirstUsableLba;
  UINT64    LastUsableLba;
  EFI_GUID  DiskGuid;
  UINT64    PartitionEntryLba;
  UINT32    NumberOfPartitionEntries;
  UINT32    SizeOfPartitionEntry;
  UINT32    PartitionEntryArrayCrc;
} GPT_HEADER;

typedef struct {
  EFI_GUID  PartitionTypeGuid;
  EFI_GUID  UniquePartitionGuid;
  UINT64    StartingLba;
  UINT64    EndingLba;
  UINT64    Attributes;
  CHAR16    PartitionName[36];
} GPT_ENTRY;
#pragma pack()

STATIC CONST UINT64  GptSignature = 0x5452415020494645ULL;   /* "EFI PART" */

STATIC
VOID
PrintDevice (
  IN EFI_HANDLE             Handle,
  IN EFI_BLOCK_IO_PROTOCOL  *BlockIo,
  IN UINTN                  Index
  )
{
  EFI_STATUS  Status;
  GPT_HEADER  Header;
  GPT_ENTRY   *Entries;
  UINTN       EntryBytes;
  UINT32      Entry;
  UINTN       MediaId;

  if ((BlockIo->Media == NULL) || !BlockIo->Media->MediaPresent) {
    return;
  }

  MediaId = BlockIo->Media->MediaId;
  Status  = BlockIo->ReadBlocks (BlockIo, MediaId, 1, sizeof (Header), &Header);
  if (EFI_ERROR (Status) || (Header.Signature != GptSignature)) {
    return;
  }

  Print (L"\r\n[%u] block=%u priv=%u start=%Lu last=%Lu entries@%Lu n=%u size=%u\r\n",
         (UINT32)Index, BlockIo->Media->BlockSize, BlockIo->Media->LastBlock,
         Header.FirstUsableLba, Header.LastUsableLba,
         Header.PartitionEntryLba, Header.NumberOfPartitionEntries,
         Header.SizeOfPartitionEntry);

  if ((Header.SizeOfPartitionEntry < sizeof (GPT_ENTRY)) ||
      (Header.NumberOfPartitionEntries == 0) ||
      (Header.NumberOfPartitionEntries > 256))
  {
    return;
  }

  EntryBytes = Header.SizeOfPartitionEntry * Header.NumberOfPartitionEntries;
  Entries    = AllocatePool (EntryBytes);
  if (Entries == NULL) {
    return;
  }

  Status = BlockIo->ReadBlocks (BlockIo, MediaId, Header.PartitionEntryLba, EntryBytes, Entries);
  if (EFI_ERROR (Status)) {
    FreePool (Entries);
    return;
  }

  for (Entry = 0; Entry < Header.NumberOfPartitionEntries; Entry++) {
    GPT_ENTRY  *Item = (GPT_ENTRY *)((UINT8 *)Entries + Entry * Header.SizeOfPartitionEntry);
    BOOLEAN    Zero  = TRUE;
    UINTN      Byte;

    for (Byte = 0; Byte < sizeof (EFI_GUID); Byte++) {
      if (((UINT8 *)&Item->PartitionTypeGuid)[Byte] != 0) {
        Zero = FALSE;
        break;
      }
    }

    if (Zero) {
      continue;
    }

    {
      CHAR16  Name[37];

      /* The name is UTF-16LE, NUL padded; copy with a guaranteed terminator. */
      CopyMem (Name, Item->PartitionName, sizeof (Item->PartitionName));
      Name[36] = L'\0';
      Print (L"  %2u %s  lba %Lu..%Lu  (%Lu)\r\n",
             (UINT32)(Entry + 1), Name,
             Item->StartingLba, Item->EndingLba,
             Item->EndingLba - Item->StartingLba + 1);
    }
  }

  FreePool (Entries);
}

EFI_STATUS
EFIAPI
GptDumpEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS             Status;
  EFI_HANDLE             *Handles;
  UINTN                  Count;
  UINTN                  Index;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  &Count,
                  &Handles
                  );
  if (EFI_ERROR (Status)) {
    Print (L"GPTDUMP: no block devices (%r)\r\n", Status);
    gBS->Stall (10 * 1000 * 1000);
    return EFI_SUCCESS;
  }

  Print (L"\r\nGPTDUMP: %u block device(s)\r\n", (UINT32)Count);
  for (Index = 0; Index < Count; Index++) {
    EFI_BLOCK_IO_PROTOCOL  *BlockIo;

    Status = gBS->HandleProtocol (Handles[Index], &gEfiBlockIoProtocolGuid, (VOID **)&BlockIo);
    if (!EFI_ERROR (Status) && (BlockIo != NULL)) {
      PrintDevice (Handles[Index], BlockIo, Index);
    }
  }

  FreePool (Handles);
  Print (L"\r\nGPTDUMP: done; holding the screen\r\n");
  /* Hold the output long enough to photograph it. */
  gBS->Stall (30 * 1000 * 1000);

  return EFI_SUCCESS;
}
