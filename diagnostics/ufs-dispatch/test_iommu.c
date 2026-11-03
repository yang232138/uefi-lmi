#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
typedef uint8_t UINT8; typedef uint32_t UINT32; typedef uint64_t UINT64; typedef uintptr_t UINTN;
typedef unsigned char BOOLEAN; typedef char CHAR8; typedef void VOID;
typedef struct {UINT32 A; uint16_t B,C; unsigned char D[8];} EFI_GUID;
#define STATIC static
#define EFIAPI
#define MAX_UINT32 UINT32_MAX
#define CopyMem memcpy
#define DEBUG(x) ((void)0)
static int CompareGuid(const EFI_GUID*a,const EFI_GUID*b) {return !memcmp(a,b,sizeof(*a));}
static VOID *published;
static int CoreInstallConfigurationTable(EFI_GUID*g,VOID*p) {(void)g;published=p;return 0;}
static BOOLEAN enabled;
BOOLEAN LmiUfsObserverEnabled(VOID) {return enabled;}
#include "IommuObserve.inc"
static UINT32 cc,fc,ac,gc,result,mode,arid,flags;
static VOID *expected; static VOID **out_expected; static CHAR8 *name; static UINT64 object[5];
static UINT32 EFIAPI create(VOID **out) {assert(out==out_expected);cc++;if(!result&&out)*out=object;return result;}
static UINT32 EFIAPI configure(VOID*d,UINT32 m) {assert(d==expected&&m==mode);fc++;if(!result)*(UINT32*)((UINT8*)d+0x20)=m?0x9f00e0:0xe0;return result;}
static UINT32 EFIAPI attach(VOID*d,CHAR8*n,UINT32 a,UINT32 f) {assert(d==expected&&n==name&&a==arid&&f==flags);ac++;return result;}
static LMI_FUNCTIONS original={.Create=create,.Configure=configure,.Attach=attach};
static LMI_FUNCTIONS **get_expected; static int null_table;
static VOID EFIAPI get(LMI_FUNCTIONS**f) {assert(f==get_expected);gc++;if(f)*f=null_table?NULL:&original;}
int main(void) {
  _Static_assert(sizeof(LMI_FUNCTIONS)==72,"table ABI");
  _Static_assert(offsetof(LMI_FUNCTIONS,Attach)==16,"attach ABI");
  _Static_assert(offsetof(LMI_FUNCTIONS,Configure)==64,"configure ABI");
  LmiIommuInitialize();assert(published==&mLmiIommu);
  LMI_PROTOCOL protocol={1,get,&object},saved=protocol;
  EFI_GUID wrong={0}; VOID *p=&protocol;
  LmiIommuObserveLocated(&mLmiHalGuid,&p);assert(p==&protocol&&!gc);
  enabled=1;LmiIommuObserveLocated(&wrong,&p);assert(p==&protocol);
  protocol.Revision=2;LmiIommuObserveLocated(&mLmiHalGuid,&p);assert(p==&protocol);protocol=saved;
  LmiIommuObserveLocated(&mLmiHalGuid,&p);assert(p==&mLmiProxyProtocol&&!gc);
  assert(mLmiProxyProtocol.Revision==1&&mLmiProxyProtocol.Slot2==protocol.Slot2);
  LMI_FUNCTIONS *f=NULL;get_expected=&f;((LMI_PROTOCOL*)p)->GetFunctions(&f);
  assert(gc==1&&f==&mLmiProxyFunctions);
  assert(f->Delete==original.Delete&&f->Detach==original.Detach&&f->SetConfig==original.SetConfig&&f->Slot5==original.Slot5&&f->Slot6==original.Slot6&&f->Slot7==original.Slot7);
  VOID *domain=NULL;out_expected=&domain;result=0;
  assert(f->Create(&domain)==0&&domain==&object&&cc==1);
  assert(mLmiIommu.Records[0].Kind==1&&mLmiIommu.Records[0].Completed==1&&mLmiIommu.Records[0].Domain==(UINTN)domain);
  expected=domain;mode=0;result=0;
  assert(f->Configure(domain,mode)==result&&fc==1);
  assert(mLmiIommu.Records[1].ReturnCode==0&&mLmiIommu.Records[1].DomainAttributes==0xe0);
  mode=1;result=0xdeadbeef;
  assert(f->Configure(domain,mode)==result&&fc==2);
  assert(mLmiIommu.Records[2].ReturnCode==result&&mLmiIommu.Records[2].Argument==1&&mLmiIommu.Records[2].DomainAttributes==0);
  name="UFS0";arid=0x10;flags=0xabcdef01;result=0x18;
  assert(f->Attach(domain,name,arid,flags)==result&&ac==1);
  assert(mLmiIommu.Records[3].ReturnCode==0x18&&mLmiIommu.Records[3].Arid==0x10&&mLmiIommu.Records[3].Flags==flags);
  result=0x13;assert(f->Create(&domain)==result&&cc==2);
  assert(mLmiIommu.Records[4].Domain==0&&domain==object);
  enabled=0;UINT32 count=mLmiIommu.Count;assert(f->Attach(domain,name,arid,flags)==result);assert(ac==2&&mLmiIommu.Count==count);
  f=NULL;((LMI_PROTOCOL*)p)->GetFunctions(&f);assert(f==&original&&gc==2);
  enabled=1;null_table=1;((LMI_PROTOCOL*)p)->GetFunctions(&f);assert(!f&&gc==3);null_table=0;
  ((LMI_PROTOCOL*)p)->GetFunctions(&f);assert(gc==4);
  for(unsigned i=0;i<100;i++)assert(f->Configure(domain,mode)==result);
  assert(fc==102&&mLmiIommu.Count==LMI_IOMMU_CAPACITY&&mLmiIommu.Dropped==81);
  assert(!memcmp(&protocol,&saved,sizeof(protocol)));
  puts("PASS: ABI; exact once forwarding; unchanged arguments and errors; scope; null; bounds; original preserved");return 0;
}
