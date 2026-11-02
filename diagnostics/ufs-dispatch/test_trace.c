/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef uint8_t UINT8;
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
#define IN
#define OPTIONAL
#define STATIC static
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
#include "DispatcherTrace.inc"
#define CHECK(x) do {if(!(x)) {fprintf(stderr,"failed line %d: %s\n",__LINE__,#x);exit(1);} } while(0)
int main(void) {
  LmiUfsTraceInitialize();
  CHECK(Published==&mLmiTrace && mLmiTrace.Count==1);
  CHECK(mLmiTrace.Size==sizeof(mLmiTrace) && sizeof(LMI_TRACE_RECORD)==32);
  EFI_CORE_DRIVER_ENTRY other={0};
  LmiUfsRecord(&other,LmiTraceLoadEnd,123);
  CHECK(mLmiTrace.Count==1);
  EFI_CORE_DRIVER_ENTRY ufs={0};ufs.FileName=mLmiUfsGuid;
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
  puts("trace tests passed: publication, target filtering, flags, 64-bit status, sequence, capacity and saturation");
  return 0;
}
