/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * View normal dispatcher records. No disk, driver-start or controller methods.
 */
#include <Uefi.h>
#include "UfsDispatchTrace.h"
#include "UfsSerialLog.h"
#include "LogText.inc"
#include "IortProbe.h"
#include "IommuObserve.h"
static EFI_GUID IommuGuid = LMI_IOMMU_GUID;
static const LMI_IOMMU_TABLE *Iommu;

static EFI_SYSTEM_TABLE *ST;
static EFI_GUID TraceGuid = LMI_TRACE_GUID;
static EFI_GUID LogGuid = LMI_LOG_GUID;
static EFI_GUID IortGuid = LMI_IORT_PROBE_GUID;
static const LMI_IORT_PROBE *Iort;
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
static VOID trace_page(const LMI_TRACE_TABLE *t,UINTN p) {
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
  print("AUTO DISPLAY v1: next page in 15 seconds.");
  print("Pages repeat automatically. No keyboard needed.");
}
static VOID iort_page(VOID) {
  if(ST->ConOut) ST->ConOut->ClearScreen(ST->ConOut);
  print("LMIPRO IORT READONLY PROBE v1");
  print("No DT writes. Named RAM regions only, max 1 MiB each.");
  if(!Iort) {print("Probe table missing or invalid. No inference possible.");return;}
  for(UINTN i=0;i<LMI_IORT_PROBE_REGIONS;i++) {
    const LMI_IORT_REGION *r=&Iort->Regions[i];
    begin(r->Name);append(" lookup=0x");number(r->LookupStatus,16);print(Line);
    begin(" base=0x");number(r->Address,16);append(" size=0x");number(r->Length,16);print(Line);
    begin(" scanned=0x");number(r->Scanned,16);append(" fdt=");number(r->ValidFdt,10);append(" skip=");number(r->Skipped,10);print(Line);
    begin(" iort=0x");number((UINT32)r->IortOffset,16);append(" ufs=0x");number((UINT32)r->UfsOffset,16);print(Line);
    begin(" CacheCoherency len=0x");number((UINT32)r->CacheLength,16);append(" value=0x");number(r->CacheValue,16);print(Line);
  }
  print("lookup 800000000000000e = named region absent");
  print("iort/ufs ffffffff = absent or no valid DT examined");
  for(UINTN i=0;i<Iort->NodeCount;i++) {begin("IORT child: ");append(Iort->NodeNames[i]);print(Line);}
  begin("additional IORT children=");number(Iort->NodesDropped,10);print(Line);
  print("AUTO DISPLAY v1: next page in 15 seconds.");
}
static VOID iommu_page(VOID) {
  if(ST->ConOut) ST->ConOut->ClearScreen(ST->ConOut);
  print("LMIPRO IOMMU ORIGINAL CALLS v1");
  print("Original UFS calls, same arguments and real return codes.");
  print("Domain attrs are read after Configure returns success.");
  print("DAL UFS0 IORT CacheCoherency=0 (unchanged vendor table).");
  if(!Iommu) {print("Observer table missing or invalid. No inference possible.");return;}
  begin("located=");number(Iommu->Located,10);append(" wrapped=");number(Iommu->Wrapped,10);
  append(" records=");number(Iommu->Count,10);append(" dropped=");number(Iommu->Dropped,10);print(Line);
  begin("original protocol=0x");number(Iommu->Protocol,16);print(Line);
  begin("original functions=0x");number(Iommu->Functions,16);print(Line);
  for(UINTN i=0;i<Iommu->Count;i++) {
    const LMI_IOMMU_RECORD *r=&Iommu->Records[i];
    begin("#");number(i+1,10);append(r->Kind==1?" Create":r->Kind==2?" Configure":" Attach");
    append(" returned=");number(r->Completed,10);append(" code=0x");number(r->ReturnCode,16);print(Line);
    begin(" domain=0x");number(r->Domain,16);append(r->Kind==2?" mode=0x":" arg=0x");number(r->Argument,16);print(Line);
    if(r->Kind==2 && r->Completed && r->ReturnCode==0) {
      begin("  runtime domain attrs@+0x20=0x");number(r->DomainAttributes,16);print(Line);
    }
    if(r->Kind==3) {begin(" arid=0x");number(r->Arid,16);append(" flags=0x");number(r->Flags,16);print(Line);}
  }
  print("Return codes are vendor UINT32, not EFI_STATUS.");
  print("returned=0 means no completed return was observed.");
  print("No added vendor calls, parameter changes or disk tests.");
  print("AUTO DISPLAY v1: stays 25 seconds; no keyboard needed.");
  print("This page returns every cycle.");
}
static VOID page(const LMI_TRACE_TABLE *t,const LMI_SERIAL_LOG *log,UINTN p,UINTN lp) {
  if(p==0) {iommu_page();return;}
  p--;
  if(p==0) {iort_page();return;}
  p--;
  if(p>=lp) {trace_page(t,p-lp);return;}
  if(ST->ConOut) ST->ConOut->ClearScreen(ST->ConOut);
  print("LMIPRO UFS ORIGINAL SERIAL LOG v1");
  print("Captured only during the original UFS entry.");
  if(!log) {
    print("Log buffer missing or invalid. No failure inferred.");
  } else {
    begin("bytes=");number(log->Count,10);append(" dropped=");number(log->Dropped,10);
    append(" calls=");number(log->Calls,10);print(Line);
    begin("log page ");number(p+1,10);append(" / ");number(lp,10);print(Line);
    if(!log->Count) print("No serial text captured. This is inconclusive.");
    UINTN at=0,row=0;char out[LMI_LOG_COLUMNS+1];
    while(at<log->Count && row<(p+1)*LMI_LOG_ROWS) {
      at=LogLine(log,at,out);
      if(row>=p*LMI_LOG_ROWS) print(out);
      row++;
    }
  }
  print("AUTO DISPLAY v1: next page in 15 seconds.");
  print("Pages repeat automatically. No keyboard needed.");
  print("Empty logs do not prove successful initialization.");
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
  const LMI_SERIAL_LOG *log=NULL;
  for(UINTN i=0;i<ST->NumberOfTableEntries;i++) {
    if(equal(&ST->ConfigurationTable[i].VendorGuid,&IommuGuid)) Iommu=ST->ConfigurationTable[i].VendorTable;
    if(equal(&ST->ConfigurationTable[i].VendorGuid,&IortGuid)) Iort=ST->ConfigurationTable[i].VendorTable;
    if(equal(&ST->ConfigurationTable[i].VendorGuid,&TraceGuid)) {
      trace=ST->ConfigurationTable[i].VendorTable;
    }
    if(equal(&ST->ConfigurationTable[i].VendorGuid,&LogGuid)) log=ST->ConfigurationTable[i].VendorTable;
  }
  EFI_GUID target=LMI_UFS_GUID;
  if(trace && (trace->Signature!=LMI_TRACE_SIGNATURE || trace->Version!=LMI_TRACE_VERSION ||
     trace->Size!=sizeof(*trace) || trace->Capacity!=LMI_TRACE_CAPACITY ||
     trace->Count>trace->Capacity || !equal(&trace->Target,&target))) trace=NULL;
  if(log && (log->Signature!=LMI_LOG_SIGNATURE || log->Version!=1 || log->Size!=sizeof(*log) ||
      log->Capacity!=LMI_LOG_CAPACITY || log->Count>log->Capacity || log->Enabled)) log=NULL;
  if(Iort && (Iort->Signature!=LMI_IORT_PROBE_SIGNATURE || Iort->Version!=1 ||
      Iort->Size!=sizeof(*Iort) || Iort->ReadOnly!=1 || Iort->NodeCount>LMI_IORT_PROBE_NODES)) Iort=NULL;
  if(Iommu && (Iommu->Signature!=LMI_IOMMU_SIGNATURE || Iommu->Version!=1 ||
     Iommu->Size!=sizeof(*Iommu) || Iommu->Count>LMI_IOMMU_CAPACITY)) Iommu=NULL;
  UINTN lp=LogPages(log),total=2+lp+(trace?(trace->Count+11)/12:1);
  UINTN current=0;page(trace,log,current,lp);
  for(;;) {
    ST->BootServices->Stall(current==0 ? 25000000 : 15000000);
    current=(current+1)%total;
    page(trace,log,current,lp);
  }
}
