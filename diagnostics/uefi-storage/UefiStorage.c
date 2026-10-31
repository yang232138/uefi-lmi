/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Standalone EFI application, loaded by UniXNU's documented type="efi" entry.
 * V3 adds authenticated FV identity + normal LoadImage/UnloadImage probe.
 * Never calls StartImage or any UFS/controller method. No MMIO or disk writes.
 */
#include <Uefi.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>
#include <Protocol/DevicePathToText.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DriverBinding.h>
#include <Pi/PiFirmwareFile.h>
#include <Pi/PiFirmwareVolume.h>
#include <Protocol/FirmwareVolume2.h>
#include "StorageCore.h"
#include "FirmwareNames.h"

static EFI_SYSTEM_TABLE *ST;
static EFI_GUID BlockGuid=EFI_BLOCK_IO_PROTOCOL_GUID;
static EFI_GUID PathGuid=EFI_DEVICE_PATH_PROTOCOL_GUID;
static EFI_GUID TextGuid=EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID;
static EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *PathText;
static EFI_GUID LoadedGuid=EFI_LOADED_IMAGE_PROTOCOL_GUID;
static EFI_GUID BindingGuid=EFI_DRIVER_BINDING_PROTOCOL_GUID;
static UINTN SmemPresent,SpmiPresent,UfsLoaded,UfsBindings,LoadedCount,BindingCount;
static EFI_GUID FvGuid=EFI_FIRMWARE_VOLUME2_PROTOCOL_GUID;
static EFI_GUID UfsGuid={0x0d35cd8e,0x97ea,0x4f9a,{0x96,0xaf,0x0f,0x0d,0x89,0xf7,0x65,0x67}};
static EFI_HANDLE ThisImage;
static UINTN FvCount,FvMatches,UfsHashMatch,LoadAttempted,UnloadAttempted;
static EFI_STATUS FvReadStatus=EFI_NOT_READY,LoadStatus=EFI_NOT_READY,UnloadStatus=EFI_NOT_READY;
static char Logs[512][160];
static UINTN LogCount;
static UINTN AllReads,ReadFailures,PhysicalDisks,Partitions,Targets,Passed;
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
  clear();output("LMIPRO UEFI LOADER PROBE v3");output("Load/unload only; UFS entry NOT executed");
  begin("DEPEX SMEM=");number(SmemPresent,10);kv(" SPMI=",SpmiPresent,10);output(Text);
  begin("UFS image=");number(UfsLoaded,10);kv(" bindings=",UfsBindings,10);output(Text);
  begin("All images=");number(LoadedCount,10);kv(" bindings=",BindingCount,10);output(Text);
  begin("FV count=");number(FvCount,10);kv(" UFS copies=",FvMatches,10);kv(" hash=",UfsHashMatch,10);output(Text);
  begin("FV read status=0x");number(FvReadStatus,16);output(Text);
  begin("Load attempted=");number(LoadAttempted,10);kv(" status=0x",LoadStatus,16);output(Text);
  begin("Unload attempted=");number(UnloadAttempted,10);kv(" status=0x",UnloadStatus,16);output(Text);
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
  if(LoadAttempted) output(EFI_ERROR(LoadStatus)?"RESULT: UFSDxe LOAD REJECTED":"RESULT: UFSDxe LOAD OK; NOT STARTED");
  else if(!UfsHashMatch) output("RESULT: UFS FV IDENTITY NOT CONFIRMED");
  else output("RESULT: LOADER TEST SKIPPED; SEE LOG");
  output("Not a full image hash or root mount.");output("N/P: log pages  S: summary  Esc: menu");output("No automatic reboot. Keep this screen.");
}
/* Build exactly one FV-file path from a bounded, single-instance FV path. */
static EFI_DEVICE_PATH_PROTOCOL *ufs_path(EFI_HANDLE h) {
  EFI_DEVICE_PATH_PROTOCOL *dp=NULL;
  if(EFI_ERROR(ST->BootServices->HandleProtocol(h,&PathGuid,(VOID **)&dp))||!dp) return NULL;
  UINTN pos=0;BOOLEAN ended=FALSE;
  while(pos+4<=4000) {
    UINT8 *n=(UINT8 *)dp+pos;UINTN len=(UINTN)n[2]+((UINTN)n[3]<<8);
    if(len<4||len>4000-pos) return NULL;
    if(n[0]==END_DEVICE_PATH_TYPE) {
      if(n[1]!=END_ENTIRE_DEVICE_PATH_SUBTYPE||len!=4) return NULL;
      ended=TRUE;break;
    }
    if(n[0]==MEDIA_DEVICE_PATH&&n[1]==MEDIA_PIWG_FW_FILE_DP) return NULL;
    pos+=len;
  }
  if(!ended) return NULL;
  UINTN size=pos+sizeof(MEDIA_FW_VOL_FILEPATH_DEVICE_PATH)+4;
  VOID *buf=NULL;if(EFI_ERROR(ST->BootServices->AllocatePool(EfiBootServicesData,size,&buf))||!buf) return NULL;
  ByteCopy(buf,dp,pos);UINT8 *n=(UINT8 *)buf+pos;
  n[0]=MEDIA_DEVICE_PATH;n[1]=MEDIA_PIWG_FW_FILE_DP;n[2]=(UINT8)sizeof(MEDIA_FW_VOL_FILEPATH_DEVICE_PATH);n[3]=0;
  ByteCopy(n+4,&UfsGuid,16);n+=sizeof(MEDIA_FW_VOL_FILEPATH_DEVICE_PATH);
  n[0]=END_DEVICE_PATH_TYPE;n[1]=END_ENTIRE_DEVICE_PATH_SUBTYPE;n[2]=4;n[3]=0;
  return buf;
}
static VOID probe_loader(void) {
  static const UINT8 expected[32]={0xff,0xea,0xed,0x46,0x7f,0x82,0x51,0xb7,0xe3,0x0a,0x45,0x07,0x5d,0xa8,0x4a,0x1c,0x56,0x3e,0x2b,0xac,0x7d,0xc4,0xbe,0x0f,0x79,0xf0,0xed,0x49,0xa8,0x8b,0x8d,0xc9};
  EFI_HANDLE *hs=NULL,target=NULL;UINTN n=0;
  EFI_STATUS st=ST->BootServices->LocateHandleBuffer(ByProtocol,&FvGuid,NULL,&n,&hs);
  begin("FV enumeration status=0x");number(st,16);kv(" count=",n,10);emit();
  if(EFI_ERROR(st)) return;FvCount=n;
  for(UINTN i=0;i<n&&i<32;i++) {
    EFI_FIRMWARE_VOLUME2_PROTOCOL *fv=NULL;
    if(EFI_ERROR(ST->BootServices->HandleProtocol(hs[i],&FvGuid,(VOID **)&fv))||!fv||!fv->ReadSection) continue;
    VOID *pe=NULL;UINTN size=0;UINT32 auth=0;
    st=fv->ReadSection(fv,&UfsGuid,EFI_SECTION_PE32,0,&pe,&size,&auth);
    begin("FV ");number(i,10);kv(" UFS ReadSection=0x",st,16);kv(" bytes=",size,10);kv(" auth=0x",auth,16);emit();
    if(!EFI_ERROR(st)&&pe) {
      FvMatches++;FvReadStatus=st;
      if(size==118784) {
        UINT8 digest[32];ro_sha256(pe,size,digest);BOOLEAN same=TRUE;
        for(UINTN j=0;j<32;j++) if(digest[j]!=expected[j]) same=FALSE;
        begin("UFSDxe exact extracted PE hash match=");number(same,10);emit();
        if(same) {UfsHashMatch++;target=hs[i];}
      }
    } else if(st!=EFI_NOT_FOUND) FvReadStatus=st;
    if(pe) ST->BootServices->FreePool(pe);
  }
  if(hs) ST->BootServices->FreePool(hs);
  if(FvMatches!=1||UfsHashMatch!=1||!target||UfsLoaded||UfsBindings) {record("Load skipped: ambiguous/missing identity or UFS already loaded");return;}
  EFI_DEVICE_PATH_PROTOCOL *path=ufs_path(target);
  if(!path) {record("Load skipped: FV device path unavailable/malformed");return;}
  EFI_HANDLE image=NULL;
  record("PROBE: normal LoadImage only; no StartImage, Dispatch or ConnectController");
  LoadAttempted=1;LoadStatus=ST->BootServices->LoadImage(FALSE,ThisImage,path,NULL,0,&image);
  begin("LoadImage return=0x");number(LoadStatus,16);kv(" handle=0x",(UINTN)image,16);emit();
  if(image) {
    /* In pinned CoreUnloadImage, a never-started image is freed without invoking
       a vendor unload entry. Never call StartImage to satisfy unload semantics. */
    UnloadAttempted=1;UnloadStatus=ST->BootServices->UnloadImage(image);
    begin("UnloadImage return=0x");number(UnloadStatus,16);emit();
  }
  ST->BootServices->FreePool(path);
  record("Probe complete. UFSDxe entry and disk methods were not invoked.");
}
static VOID logpage(UINTN page) {
  clear();begin("READ-ONLY LOG PAGE ");number(page+1,10);output(Text);
  UINTN first=page*20;for(UINTN i=first;i<LogCount&&i<first+20;i++) output(Logs[i]);
  output("N/P: next/previous  S: summary  Esc: menu");
}
static BOOLEAN guid_equal(const EFI_GUID *a,const EFI_GUID *b) {
  const UINT8 *x=(const UINT8 *)a,*y=(const UINT8 *)b;
  for(UINTN i=0;i<16;i++) if(x[i]!=y[i]) return FALSE;return TRUE;
}
static VOID hexwidth(UINT64 v,UINTN digits) {
  for(UINTN i=digits;i;i--) {char t[2]={"0123456789abcdef"[(v>>((i-1)*4))&15],0};append(t);}
}
static VOID guid_text(const EFI_GUID *g) {
  hexwidth(g->Data1,8);append("-");hexwidth(g->Data2,4);append("-");hexwidth(g->Data3,4);append("-");
  for(UINTN i=0;i<8;i++) {if(i==2) append("-");hexwidth(g->Data4[i],2);}
}
static BOOLEAN file_guid(EFI_DEVICE_PATH_PROTOCOL *dp,EFI_GUID *g) {
  UINTN used=0;
  while(dp&&used+sizeof(*dp)<=4096) {
    UINTN len=(UINTN)dp->Length[0]+((UINTN)dp->Length[1]<<8);
    if(len<sizeof(*dp)||len>4096-used) return FALSE;
    if(dp->Type==MEDIA_DEVICE_PATH&&dp->SubType==MEDIA_PIWG_FW_FILE_DP&&len==sizeof(MEDIA_FW_VOL_FILEPATH_DEVICE_PATH)) {
      ByteCopy(g,(UINT8 *)dp+sizeof(*dp),sizeof(*g));return TRUE;
    }
    if(dp->Type==END_DEVICE_PATH_TYPE) return FALSE;
    used+=len;dp=(EFI_DEVICE_PATH_PROTOCOL *)((UINT8 *)dp+len);
  }
  return FALSE;
}
static BOOLEAN describe_image(EFI_HANDLE image,const char *prefix,UINTN index) {
  EFI_LOADED_IMAGE_PROTOCOL *li=NULL;EFI_GUID g;
  EFI_STATUS st=ST->BootServices->HandleProtocol(image,&LoadedGuid,(VOID **)&li);
  begin(prefix);number(index,10);
  if(EFI_ERROR(st)||!li) {kv(" LoadedImage status=0x",st,16);emit();return FALSE;}
  if(!file_guid(li->FilePath,&g)) {record(Text);record("  no FV file GUID (application or other path)");return FALSE;}
  append(" ");guid_text(&g);emit();
  BOOLEAN ufs=FALSE;
  for(UINTN i=0;i<sizeof(FirmwareNames)/sizeof(FirmwareNames[0]);i++) if(guid_equal(&g,&FirmwareNames[i].guid)) {
    begin("  FD module: ");append(FirmwareNames[i].name);emit();
    const char *n=FirmwareNames[i].name;ufs=n[0]=='U'&&n[1]=='F'&&n[2]=='S'&&n[3]=='D'&&n[4]=='x'&&n[5]=='e'&&n[6]==0;break;
  }
  return ufs;
}
static VOID inventory(void) {
  struct {const char *name;EFI_GUID guid;} probes[]={
    {"SMEM",{0xf4e5c7d0,0xd239,0x47cb,{0xaa,0xcd,0x7f,0x66,0xef,0x76,0x32,0x38}}},
    {"SPMI",{0xfa5f306b,0xf47d,0x4ac4,{0xa4,0x7d,0x88,0x2f,0x82,0x04,0xec,0x30}}},
    {"Clock",{0x241afae6,0x885f,0x4f6c,{0xa7,0xea,0xc2,0x8e,0xab,0x79,0xc3,0xe5}}},
    {"PlatformInfo",{0x157a5c45,0x21b2,0x43c5,{0xba,0x7c,0x82,0x2f,0xee,0x5f,0xe5,0x99}}},
    {"SCM",{0x77ed108d,0x8524,0x4b8b,{0x9d,0x2e,0x34,0x98,0x7a,0xec,0xb9,0xc1}}},
    {"MemCardInfo",{0x85c1f7d2,0xbce6,0x4f31,{0x8f,0x4d,0xd3,0x7e,0x03,0xd0,0x5e,0xaa}}}
  };
  record("Runtime protocol inventory; no protocol methods invoked");
  for(UINTN i=0;i<sizeof(probes)/sizeof(probes[0]);i++) {
    VOID *p=NULL;EFI_STATUS st=ST->BootServices->LocateProtocol(&probes[i].guid,NULL,&p);
    BOOLEAN present=!EFI_ERROR(st)&&p!=NULL;
    if(i==0) SmemPresent=present;if(i==1) SpmiPresent=present;
    begin("PROTO ");append(probes[i].name);kv(" present=",present,10);kv(" status=0x",st,16);emit();
  }
  EFI_HANDLE *hs=NULL;UINTN n=0;
  EFI_STATUS st=ST->BootServices->LocateHandleBuffer(ByProtocol,&LoadedGuid,NULL,&n,&hs);
  begin("LoadedImage enumeration status=0x");number(st,16);kv(" count=",n,10);emit();
  if(!EFI_ERROR(st)) {LoadedCount=n;for(UINTN i=0;i<n&&i<192;i++) if(describe_image(hs[i],"IMAGE ",i)) UfsLoaded++;}
  if(hs) ST->BootServices->FreePool(hs);hs=NULL;n=0;
  st=ST->BootServices->LocateHandleBuffer(ByProtocol,&BindingGuid,NULL,&n,&hs);
  begin("DriverBinding enumeration status=0x");number(st,16);kv(" count=",n,10);emit();
  if(!EFI_ERROR(st)) {BindingCount=n;for(UINTN i=0;i<n&&i<128;i++) {
    EFI_DRIVER_BINDING_PROTOCOL *b=NULL;
    if(!EFI_ERROR(ST->BootServices->HandleProtocol(hs[i],&BindingGuid,(VOID **)&b))&&b&&describe_image(b->ImageHandle,"BINDING ",i)) UfsBindings++;
  }}
  if(hs) ST->BootServices->FreePool(hs);
  record("LoadedImage presence does not prove successful StartImage.");
}
EFI_STATUS EFIAPI UefiMain(EFI_HANDLE image,EFI_SYSTEM_TABLE *table) {
  ThisImage=image;ST=table;if(!ST||!ST->BootServices) return EFI_INVALID_PARAMETER;
  ST->BootServices->SetWatchdogTimer(0,0,0,NULL);setup_console();
  record("LMIPRO UEFI LOADER PROBE v3");
  record("No WriteBlocks, controller reset or direct MMIO.");
  ST->BootServices->LocateProtocol(&TextGuid,NULL,(VOID **)&PathText);
  inventory();
  probe_loader();
  EFI_HANDLE *handles=NULL;UINTN count=0;
  EFI_STATUS st=ST->BootServices->LocateHandleBuffer(ByProtocol,&BlockGuid,NULL,&count,&handles);LastStatus=st;
  if(!EFI_ERROR(st)) for(UINTN i=0;i<count&&i<128;i++) {
    EFI_BLOCK_IO_PROTOCOL *io=NULL;
    if(EFI_ERROR(ST->BootServices->HandleProtocol(handles[i],&BlockGuid,(VOID **)&io))||!io||!io->Media) continue;
    EFI_BLOCK_IO_MEDIA *m=io->Media;
    begin("HANDLE ");number(i,10);kv(" bs=",m->BlockSize,10);kv(" last=0x",m->LastBlock,16);emit();
    begin("present=");number(m->MediaPresent,10);kv(" partition=",m->LogicalPartition,10);kv(" ioalign=",m->IoAlign,10);kv(" readonly=",m->ReadOnly,10);emit();show_path(handles[i]);
    if(m->LogicalPartition) {Partitions++;continue;}PhysicalDisks++;
    record("V3: physical medium enumeration only; ReadBlocks disabled");
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
