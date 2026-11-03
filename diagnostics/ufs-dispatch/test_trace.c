/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef uint8_t UINT8;
typedef uintptr_t UINTN;
typedef char CHAR8;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uint64_t EFI_STATUS;
typedef unsigned char BOOLEAN;
typedef void VOID;
typedef struct {UINT32 Data1;uint16_t Data2,Data3;UINT8 Data4[8];} EFI_GUID;
typedef struct {
  EFI_GUID FileName;
  BOOLEAN Dependent,Scheduled,Initialized,Untrusted,Unrequested;
  BOOLEAN DepexProtocolError,Before,After,IsFvImage;
} EFI_CORE_DRIVER_ENTRY;
#define TRUE 1
#define FALSE 0
VOID LmiIommuInitialize(VOID) {}
#define IN
#define OPTIONAL
#define STATIC static
#define EFIAPI
#define EFI_ERROR(x) (((x)>>63)!=0)
#define MAX_UINT32 UINT32_MAX
#define BIT0 1U
#define BIT1 2U
#define BIT2 4U
#define BIT3 8U
#define BIT4 16U
#define BIT5 32U
#define BIT6 64U
#define BIT7 128U
#define BIT8 256U
#define DEBUG_ERROR 1
#define DEBUG(x) do {} while(0)
static int CompareGuid(const EFI_GUID *a,const EFI_GUID *b) {return memcmp(a,b,sizeof(*a))==0;}
static VOID *Published;
static EFI_STATUS CoreInstallConfigurationTable(EFI_GUID *g,VOID *p) {(void)g;Published=p;return 0;}
static UINTN ForwardCalls,ForwardBytes;
static UINT8 *ForwardBuffer;
static UINTN SerialPortWrite(UINT8 *b,UINTN n) {ForwardCalls++;ForwardBuffer=b;ForwardBytes=n;return 19;}
#include "SerialCapture.inc"
static UINTN FakeHob;
static int HasHob;
static VOID *GetFirstGuidHob(EFI_GUID *g) {(void)g;return HasHob?&FakeHob:NULL;}
#define GET_GUID_HOB_DATA_SIZE(h) sizeof(UINTN)
#define GET_GUID_HOB_DATA(h) (h)
#include "DispatcherTrace.inc"
#include "LogText.inc"
static EFI_STATUS TestLoad(CHAR8 *name,UINT32 version,VOID **ptr) {
  (void)version;
  if(strcmp(name,LMI_LOG_LIB_NAME)) return 0x800000000000000eULL;
  *ptr=&mLmiSerialLog;return 0;
}
#define CHECK(x) do {if(!(x)) {fprintf(stderr,"failed line %d: %s\n",__LINE__,#x);exit(1);} } while(0)
int main(void) {
  LmiUfsTraceInitialize();
  CHECK(Published==&mLmiTrace && mLmiTrace.Count==1);
  CHECK(mLmiLog==NULL);
  LMI_SHIM_LOADER loader={1,NULL,TestLoad};FakeHob=(UINTN)&loader;HasHob=1;
  LmiSerialInitialize();CHECK(mLmiLog==&mLmiSerialLog && Published==mLmiLog);
  CHECK(mLmiTrace.Size==sizeof(mLmiTrace) && sizeof(LMI_TRACE_RECORD)==32);
  EFI_CORE_DRIVER_ENTRY other={0};
  LmiUfsRecord(&other,LmiTraceLoadEnd,123);
  CHECK(mLmiTrace.Count==1);
  EFI_CORE_DRIVER_ENTRY ufs={0};ufs.FileName=mLmiUfsGuid;
  UINT8 msg[]="UFS IOMMU LocateProtocol failed 0x8000000e\r\n";
  CHECK(LmiSerialWrite(msg,2)==19 && ForwardBuffer==msg && ForwardBytes==2);
  CHECK(mLmiLog->Count==0);
  LmiUfsRecord(&ufs,LmiTraceEntryBegin,0);
  CHECK(mLmiLog->Enabled==1 && LmiUfsObserverEnabled());
  LmiSerialWrite(msg,5);LmiSerialWrite(msg+5,sizeof(msg)-6);
  CHECK(mLmiLog->Count==sizeof(msg)-1 && !memcmp(mLmiLog->Bytes,msg,sizeof(msg)-1));
  CHECK(mLmiLog->Calls==2 && ForwardCalls==3);
  char line[69];CHECK(LogLine(mLmiLog,0,line)==mLmiLog->Count);
  CHECK(!strcmp(line,"UFS IOMMU LocateProtocol failed 0x8000000e"));
  CHECK(LogPages(mLmiLog)==1);
  LmiUfsRecord(&other,LmiTraceEntryEnd,0);CHECK(mLmiLog->Enabled==1 && LmiUfsObserverEnabled());
  LmiUfsRecord(&ufs,LmiTraceEntryEnd,0);CHECK(mLmiLog->Enabled==0 && !LmiUfsObserverEnabled());
  LmiSerialWrite(NULL,0);CHECK(ForwardCalls==4 && ForwardBuffer==NULL);
  UINT8 large[LMI_LOG_CAPACITY+9];memset(large,'x',sizeof(large));
  mLmiLog->Count=0;mLmiLog->Enabled=1;
  CHECK(LmiSerialWrite(large,sizeof(large))==19);
  CHECK(mLmiLog->Count==LMI_LOG_CAPACITY && mLmiLog->Dropped==9);
  CHECK(mLmiLog->Bytes[LMI_LOG_CAPACITY-1]=='x');
  mLmiLog->Dropped=MAX_UINT32;mLmiLog->Calls=MAX_UINT32;
  LmiSerialWrite(msg,1);CHECK(mLmiLog->Dropped==MAX_UINT32 && mLmiLog->Calls==MAX_UINT32);
  CHECK(LogPages(mLmiLog)>1);
  mLmiTrace.Count=1;
  ufs.Dependent=1;ufs.DepexProtocolError=1;
  LmiUfsRecord(&ufs,LmiTraceDiscovered,0);
  CHECK(mLmiTrace.Records[1].Flags==0x21);
  ufs.Dependent=0;ufs.DepexProtocolError=0;ufs.Initialized=1;
  LmiUfsRecord(&ufs,LmiTraceEntryEnd,0x800000000000000eULL);
  CHECK(mLmiTrace.Records[2].Status==0x800000000000000eULL);
  CHECK(mLmiTrace.Records[2].Stage==LmiTraceEntryEnd && mLmiTrace.Records[2].Sequence==3);
  CHECK(mLmiTrace.Records[2].Flags==4);
  while(mLmiTrace.Count<LMI_TRACE_CAPACITY) LmiUfsRecord(&ufs,LmiTraceDependency,0);
  LMI_TRACE_RECORD saved=mLmiTrace.Records[LMI_TRACE_CAPACITY-1];
  LmiUfsRecord(&ufs,LmiTraceEntryBegin,0);
  CHECK(mLmiTrace.Count==LMI_TRACE_CAPACITY && mLmiTrace.Dropped==1);
  CHECK(memcmp(&saved,&mLmiTrace.Records[LMI_TRACE_CAPACITY-1],sizeof(saved))==0);
  mLmiTrace.Dropped=MAX_UINT32;LmiUfsRecord(&ufs,LmiTraceEntryBegin,0);
  CHECK(mLmiTrace.Dropped==MAX_UINT32);
  puts("trace+serial tests passed: missing/valid HOB, target window, fragmented text, unchanged forwarding, pages, bounded buffers, counters, flags and status");
  return 0;
}
