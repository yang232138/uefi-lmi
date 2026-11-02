/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * View normal dispatcher records. No disk, driver-start or controller methods.
 */
#include <Uefi.h>
#include "UfsDispatchTrace.h"

static EFI_SYSTEM_TABLE *ST;
static EFI_GUID TraceGuid = LMI_TRACE_GUID;
static char Line[160];
static UINTN Used;
static VOID append(const char *s) {while(*s && Used+1<sizeof(Line)) Line[Used++]=*s++;Line[Used]=0;}
static VOID number(UINT64 v,UINTN base) {
  char tmp[32];UINTN n=0;
  do {tmp[n++]="0123456789abcdef"[v%base];v/=base;}while(v && n<sizeof(tmp));
  while(n && Used+1<sizeof(Line)) Line[Used++]=tmp[--n];Line[Used]=0;
}
static VOID begin(const char *s) {Used=0;append(s);}
static VOID print(const char *s) {
  CHAR16 wide[164];UINTN n=0;
  while(s[n] && n<159) {wide[n]=(UINT8)s[n];n++;}
  wide[n++]=L'\r';wide[n++]=L'\n';wide[n]=0;
  if(ST->ConOut) ST->ConOut->OutputString(ST->ConOut,wide);
}
static BOOLEAN equal(const EFI_GUID *a,const EFI_GUID *b) {
  const UINT8 *x=(const UINT8 *)a,*y=(const UINT8 *)b;
  for(UINTN i=0;i<sizeof(*a);i++) if(x[i]!=y[i]) return FALSE;
  return TRUE;
}
static const char *stage(UINT64 s) {
  switch(s) {
  case LmiTraceInit:return "publish";
  case LmiTraceDiscovered:return "discovered";
  case LmiTraceDependency:return "dependency";
  case LmiTraceScheduled:return "scheduled";
  case LmiTraceLoadBegin:return "load begin";
  case LmiTraceLoadEnd:return "load return";
  case LmiTraceEntryBegin:return "entry begin";
  case LmiTraceEntryEnd:return "entry return";
  case LmiTraceDispatchEnd:return "dispatch end";
  case LmiTraceApriori:return "apriori";
  default:return "unknown";
  }
}
static VOID page(const LMI_TRACE_TABLE *t,UINTN p) {
  if(ST->ConOut) ST->ConOut->ClearScreen(ST->ConOut);
  print("LMIPRO ORIGINAL UFS DISPATCH v1");
  print("Observer only; no extra UFS entry or disk call.");
  if(!t) {print("Trace table missing or invalid. Do not infer UFS status.");return;}
  begin("Records=");number(t->Count,10);append(" dropped=");number(t->Dropped,10);
  append(" page=");number(p+1,10);print(Line);
  print("UFS GUID: 0d35cd8e-97ea-4f9a-96af-0f0d89f76567");
  print("begin status=NOT_READY is a marker, not a failure.");
  for(UINTN i=p*12;i<t->Count && i<(p+1)*12;i++) {
    const LMI_TRACE_RECORD *r=&t->Records[i];
    begin("#");number(r->Sequence,10);append(" ");append(stage(r->Stage));print(Line);
    begin("  status=0x");number(r->Status,16);append(" flags=0x");number(r->Flags,16);print(Line);
  }
  print("flags: dep=1 sched=2 init=4 untrusted=8");
  print("SOR=10 depexErr=20 before=40 after=80 FV=100 (hex)");
  print("N/P or arrows: pages. S: first. Esc: return.");
  print("No automatic reboot. Photograph all pages.");
}
EFI_STATUS EFIAPI UefiMain(EFI_HANDLE image,EFI_SYSTEM_TABLE *table) {
  (void)image;ST=table;
  if(!ST || !ST->BootServices) return EFI_INVALID_PARAMETER;
  ST->BootServices->SetWatchdogTimer(0,0,0,NULL);
  if(ST->ConOut && ST->ConOut->Mode) {
    UINTN best=0,score=0;
    for(INT32 i=0;i<ST->ConOut->Mode->MaxMode;i++) {
      UINTN c=0,r=0;
      if(!EFI_ERROR(ST->ConOut->QueryMode(ST->ConOut,(UINTN)i,&c,&r)) && c>=60 && c<=100 && r>=35 && c*r>score) {best=(UINTN)i;score=c*r;}
    }
    if(score) ST->ConOut->SetMode(ST->ConOut,best);
    ST->ConOut->SetAttribute(ST->ConOut,EFI_WHITE|EFI_BACKGROUND_BLACK);
    ST->ConOut->EnableCursor(ST->ConOut,FALSE);
  }
  const LMI_TRACE_TABLE *trace=NULL;
  for(UINTN i=0;i<ST->NumberOfTableEntries;i++) {
    if(equal(&ST->ConfigurationTable[i].VendorGuid,&TraceGuid)) {
      trace=ST->ConfigurationTable[i].VendorTable;break;
    }
  }
  EFI_GUID target=LMI_UFS_GUID;
  if(trace && (trace->Signature!=LMI_TRACE_SIGNATURE || trace->Version!=LMI_TRACE_VERSION ||
     trace->Size!=sizeof(*trace) || trace->Capacity!=LMI_TRACE_CAPACITY ||
     trace->Count>trace->Capacity || !equal(&trace->Target,&target))) trace=NULL;
  UINTN current=0;page(trace,current);
  if(!ST->ConIn) return EFI_UNSUPPORTED;
  for(;;) {
    UINTN index=0;
    EFI_STATUS status=ST->BootServices->WaitForEvent(1,&ST->ConIn->WaitForKey,&index);
    if(EFI_ERROR(status)) return status;
    EFI_INPUT_KEY key;
    if(EFI_ERROR(ST->ConIn->ReadKeyStroke(ST->ConIn,&key))) continue;
    if(key.ScanCode==SCAN_ESC) return EFI_SUCCESS;
    if(key.UnicodeChar==L'n'||key.UnicodeChar==L'N'||key.ScanCode==SCAN_DOWN||key.ScanCode==SCAN_RIGHT) {
      if(trace && (current+1)*12<trace->Count) current++;
    } else if(key.UnicodeChar==L'p'||key.UnicodeChar==L'P'||key.ScanCode==SCAN_UP||key.ScanCode==SCAN_LEFT) {
      if(current) current--;
    } else if(key.UnicodeChar==L's'||key.UnicodeChar==L'S') current=0;
    page(trace,current);
  }
}
