/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Standalone EFI application, loaded by UniXNU's documented type="efi" entry.
 * Calls BlockIo.ReadBlocks only. No Reset/WriteBlocks/FlushBlocks calls, no MMIO,
 * SCSI passthrough, SetVariable, ConnectController or ExitBootServices.
 */
#include <Uefi.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>
#include <Protocol/DevicePathToText.h>
#include "StorageCore.h"

static EFI_SYSTEM_TABLE *ST;
static EFI_GUID BlockGuid=EFI_BLOCK_IO_PROTOCOL_GUID;
static EFI_GUID PathGuid=EFI_DEVICE_PATH_PROTOCOL_GUID;
static EFI_GUID TextGuid=EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID;
static EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *PathText;
static char Logs[512][160];
static UINTN LogCount;
static UINTN AllReads,ReadFailures,BytesRead,PhysicalDisks,Partitions,Targets,Passed;
static RO_RESULT Last;
static EFI_STATUS LastStatus;
static char Text[160];
static UINTN Used;
static VOID *ByteCopy(VOID *d,const VOID *s,UINTN n) {
  UINT8 *a=d;const UINT8 *b=s;while(n--) *a++=*b++;return d;
}
/* Satisfy optional compiler-emitted freestanding memory helpers without a CRT. */
void *memcpy(void *d,const void *s,size_t n) {return ByteCopy(d,s,n);}
void *memset(void *d,int v,size_t n) {UINT8 *p=d;while(n--) *p++=(UINT8)v;return d;}
void *memmove(void *d,const void *s,size_t n) {
  UINT8 *a=d;const UINT8 *b=s;if(a>b&&a<b+n) {while(n) {n--;a[n]=b[n];}} else ByteCopy(d,s,n);return d;
}
static VOID append(const char *s) {while(*s&&Used+1<sizeof(Text)) Text[Used++]=*s++;Text[Used]=0;}
static VOID number(UINT64 v,unsigned base) {
  char t[32];unsigned n=0;do {t[n++]="0123456789abcdef"[v%base];v/=base;}while(v&&n<sizeof(t));
  while(n&&Used+1<sizeof(Text)) Text[Used++]=t[--n];Text[Used]=0;
}
static VOID begin(const char *s) {Used=0;Text[0]=0;append(s);}
static VOID kv(const char *s,UINT64 v,unsigned base) {append(s);number(v,base);}
static VOID output(const char *s) {
  CHAR16 w[162];UINTN i=0;while(s[i]&&i<159) {w[i]=(UINT8)s[i];i++;}w[i++]=L'\r';w[i++]=L'\n';w[i]=0;
  if(ST->ConOut) ST->ConOut->OutputString(ST->ConOut,w);
}
static VOID record(const char *s) {
  if(LogCount<512) {UINTN i=0;while(s[i]&&i<159) {Logs[LogCount][i]=s[i];i++;}Logs[LogCount++][i]=0;}
  output(s);
}
static VOID emit(void) {record(Text);}
static VOID clear(void) {if(ST->ConOut) ST->ConOut->ClearScreen(ST->ConOut);}
static VOID setup_console(void) {
  if(!ST->ConOut) return;
  UINTN best=0,score=0;
  for(INT32 i=0;i<ST->ConOut->Mode->MaxMode;i++) {
    UINTN cols=0,rows=0;
    if(!EFI_ERROR(ST->ConOut->QueryMode(ST->ConOut,(UINTN)i,&cols,&rows))&&cols>=60&&cols<=100&&rows>=25&&cols*rows>score) {best=(UINTN)i;score=cols*rows;}
  }
  if(score) ST->ConOut->SetMode(ST->ConOut,best);
  ST->ConOut->SetAttribute(ST->ConOut,EFI_WHITE|EFI_BACKGROUND_BLACK);
  ST->ConOut->EnableCursor(ST->ConOut,FALSE);clear();
}
typedef struct { EFI_BLOCK_IO_PROTOCOL *io; UINT64 base; UINT64 bytes; UINTN id; } IO_CTX;
static int read_bytes(void *context,uint64_t at,size_t n,void *dest) {
  IO_CTX *c=context;EFI_BLOCK_IO_PROTOCOL *io=c->io;
  if(!io||!io->Media||!io->ReadBlocks||!n||at>c->bytes||(UINT64)n>c->bytes-at||AllReads>=512||BytesRead>16*1024*1024) return -1;
  UINT32 bs=io->Media->BlockSize,id=io->Media->MediaId;
  if(bs<512||bs>4096||(bs&(bs-1))||!io->Media->MediaPresent) return -1;
  UINTN align=io->Media->IoAlign;if(align<2) align=1;
  if(align>1024*1024||(align&(align-1))) return -1;
  UINT64 absolute=c->base+at,start=absolute/bs*bs;
  UINTN skip=(UINTN)(absolute-start);
  if(n>131072||n+skip>131072+4096) return -1;
  UINTN len=((UINTN)n+skip+bs-1)/bs*bs;
  if(len>16*1024*1024-BytesRead) return -1;
  VOID *allocation=NULL;EFI_STATUS st=ST->BootServices->AllocatePool(EfiBootServicesData,len+align-1,&allocation);
  if(EFI_ERROR(st)||!allocation) return -1;
  VOID *buffer=(VOID *)(((UINTN)allocation+align-1)&~(align-1));
  begin("READ h=");number(c->id,10);kv(" byte=0x",absolute,16);kv(" len=",n,10);emit();
  AllReads++;BytesRead+=len;
  st=io->ReadBlocks(io,id,start/bs,len,buffer);LastStatus=st;
  begin("status=0x");number((UINT64)st,16);kv(" aligned_len=",len,10);emit();
  if(!EFI_ERROR(st)&&io->Media->MediaId==id&&io->Media->BlockSize==bs) ByteCopy(dest,(UINT8 *)buffer+skip,n);
  else {ReadFailures++;st=EFI_DEVICE_ERROR;}
  ST->BootServices->FreePool(allocation);return EFI_ERROR(st)?-1:0;
}
static VOID show_path(EFI_HANDLE h) {
  EFI_DEVICE_PATH_PROTOCOL *dp=NULL;
  if(EFI_ERROR(ST->BootServices->HandleProtocol(h,&PathGuid,(VOID **)&dp))||!dp) {record("path unavailable");return;}
  UINTN consumed=0;BOOLEAN valid_end=FALSE;EFI_DEVICE_PATH_PROTOCOL *node=dp;
  while(consumed+sizeof(*node)<=4096) {
    UINTN len=(UINTN)node->Length[0]+((UINTN)node->Length[1]<<8);
    if(len<sizeof(*node)||len>4096-consumed) {record("path malformed/too long");break;}
    if(node->Type==MESSAGING_DEVICE_PATH&&node->SubType==MSG_UFS_DP&&len==sizeof(UFS_DEVICE_PATH)) {
      UFS_DEVICE_PATH *u=(UFS_DEVICE_PATH *)node;
      begin("UFS path PUN=");number(u->Pun,10);kv(" LUN=",u->Lun,10);emit();
    }
    if(node->Type==END_DEVICE_PATH_TYPE&&node->SubType==END_ENTIRE_DEVICE_PATH_SUBTYPE&&len==sizeof(*node)) {valid_end=TRUE;break;}
    consumed+=len;node=(EFI_DEVICE_PATH_PROTOCOL *)((UINT8 *)node+len);
  }
  if(PathText&&valid_end) {
    CHAR16 *s=PathText->ConvertDevicePathToText(dp,FALSE,FALSE);
    if(s) {
      UINTN at=0;while(s[at]&&at<2048) {
        begin(at?"path+: ":"path: ");UINTN j=0;
        while(s[at]&&j<140&&at<2048) {char ch=(s[at]<=127)?(char)s[at]:'?';char z[2]={ch,0};append(z);at++;j++;}emit();
      }
      ST->BootServices->FreePool(s);
    }
  }
}
static VOID summary(void) {
  clear();output("LMIPRO UEFI STORAGE RO v1");output("ReadBlocks only / no disk writes");
  begin("Disks=");number(PhysicalDisks,10);kv(" partitions=",Partitions,10);output(Text);
  begin("Targets=");number(Targets,10);kv(" matched=",Passed,10);output(Text);
  begin("Reads=");number(AllReads,10);kv(" failures=",ReadFailures,10);output(Text);
  begin("Last EFI status=0x");number((UINT64)LastStatus,16);output(Text);
  if(Targets) {
    begin("userdata byte=0x");number(Last.userdata_offset,16);output(Text);
    begin("userdata bytes=");number(Last.userdata_bytes,10);output(Text);
    begin("Manifest=");number(Last.manifest,10);kv(" OS GPT=",Last.os_gpt,10);output(Text);
    begin("OS NX=");number(Last.os_nx,10);kv(" root sample=",Last.root_sample,10);output(Text);
    begin("SystemOS NX=");number(Last.system_nx,10);kv(" volume=",Last.system_volume,10);output(Text);
  }
  if(Targets==1&&Passed==1) output("RESULT: METADATA SAMPLES MATCH");
  else if(!Targets) output("RESULT: NO MATCHING USERDATA GPT");
  else if(Targets>1) output("RESULT: AMBIGUOUS TARGETS");
  else {output("RESULT: METADATA CHECK FAILED");output(Last.failed);}
  output("Not a full image hash or root mount.");output("N/P: log pages  S: summary  Esc: menu");output("No automatic reboot. Keep this screen.");
}
static VOID logpage(UINTN page) {
  clear();begin("READ-ONLY LOG PAGE ");number(page+1,10);output(Text);
  UINTN first=page*20;for(UINTN i=first;i<LogCount&&i<first+20;i++) output(Logs[i]);
  output("N/P: next/previous  S: summary  Esc: menu");
}
EFI_STATUS EFIAPI UefiMain(EFI_HANDLE image,EFI_SYSTEM_TABLE *table) {
  (void)image;ST=table;if(!ST||!ST->BootServices) return EFI_INVALID_PARAMETER;
  ST->BootServices->SetWatchdogTimer(0,0,0,NULL);setup_console();
  record("LMIPRO UEFI STORAGE RO v1");
  record("No WriteBlocks, controller reset or direct MMIO.");
  ST->BootServices->LocateProtocol(&TextGuid,NULL,(VOID **)&PathText);
  EFI_HANDLE *handles=NULL;UINTN count=0;
  EFI_STATUS st=ST->BootServices->LocateHandleBuffer(ByProtocol,&BlockGuid,NULL,&count,&handles);LastStatus=st;
  if(!EFI_ERROR(st)) for(UINTN i=0;i<count&&i<128;i++) {
    EFI_BLOCK_IO_PROTOCOL *io=NULL;
    if(EFI_ERROR(ST->BootServices->HandleProtocol(handles[i],&BlockGuid,(VOID **)&io))||!io||!io->Media) continue;
    EFI_BLOCK_IO_MEDIA *m=io->Media;
    begin("HANDLE ");number(i,10);kv(" bs=",m->BlockSize,10);kv(" last=0x",m->LastBlock,16);emit();
    begin("present=");number(m->MediaPresent,10);kv(" partition=",m->LogicalPartition,10);kv(" ioalign=",m->IoAlign,10);kv(" readonly=",m->ReadOnly,10);emit();show_path(handles[i]);
    if(m->LogicalPartition) {Partitions++;continue;}PhysicalDisks++;
    if(!m->MediaPresent||m->BlockSize<512||m->BlockSize>4096||(m->BlockSize&(m->BlockSize-1))||m->LastBlock==UINT64_MAX||m->LastBlock+1>UINT64_MAX/m->BlockSize) continue;
    UINT64 bytes=(m->LastBlock+1)*m->BlockSize;
    if(bytes<9382658048ULL) {record("Skip small medium (includes payload RAM disk)");continue;}
    IO_CTX context={io,0,bytes,i};RO_DISK disk={read_bytes,&context,bytes};RO_PART part={0,0};
    if(!ro_gpt(&disk,m->BlockSize,0,&part,record)) continue;
    Targets++;memset(&Last,0,sizeof(Last));Last.userdata_offset=part.offset;Last.userdata_bytes=part.bytes;
    context.base=part.offset;context.bytes=part.bytes;disk.bytes=part.bytes;
    if(ro_verify_userdata(&disk,&Last,record)) Passed++;
  }
  if(handles) ST->BootServices->FreePool(handles);
  summary();UINTN page=0;
  for(;;) {
    EFI_INPUT_KEY key;
    if(ST->ConIn&&!EFI_ERROR(ST->ConIn->ReadKeyStroke(ST->ConIn,&key))) {
      if(key.ScanCode==0x17) return EFI_SUCCESS;
      if(key.UnicodeChar==L's'||key.UnicodeChar==L'S') summary();
      if(key.UnicodeChar==L'n'||key.UnicodeChar==L'N'||key.ScanCode==2||key.ScanCode==3) {page=(page+1)*20<LogCount?page+1:0;logpage(page);}
      if(key.UnicodeChar==L'p'||key.UnicodeChar==L'P'||key.ScanCode==1||key.ScanCode==4) {if(page) page--;logpage(page);}
    }
    ST->BootServices->Stall(100000);
  }
}
