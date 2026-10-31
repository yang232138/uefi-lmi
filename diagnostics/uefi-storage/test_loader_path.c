/* Exercise the real FV path builder using fake Boot Services, no firmware. */
#include "UefiStorage.c"
#include <stdio.h>
#include <stdlib.h>
static EFI_DEVICE_PATH_PROTOCOL *TestPath;
static unsigned Allocations;
static EFI_STATUS EFIAPI test_handle(EFI_HANDLE h,EFI_GUID *g,VOID **p) {
  if(h!=(EFI_HANDLE)1||!guid_equal(g,&PathGuid)) return EFI_NOT_FOUND;
  *p=TestPath;return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI test_alloc(EFI_MEMORY_TYPE type,UINTN n,VOID **p) {
  if(type!=EfiBootServicesData||n>4096) abort();Allocations++;*p=malloc(n);return *p?EFI_SUCCESS:EFI_OUT_OF_RESOURCES;
}
static void require(int b) {if(!b) abort();}
int main(void) {
  EFI_BOOT_SERVICES bs={0};EFI_SYSTEM_TABLE table={0};bs.HandleProtocol=test_handle;bs.AllocatePool=test_alloc;table.BootServices=&bs;ST=&table;
  UINT8 path[4100]={1,4,8,0,1,2,3,4,0x7f,0xff,4,0};TestPath=(VOID *)path;
  _Static_assert(sizeof(MEDIA_FW_VOL_FILEPATH_DEVICE_PATH)==20,"FV node layout");
  EFI_DEVICE_PATH_PROTOCOL *out=ufs_path((EFI_HANDLE)1);require(out!=NULL&&Allocations==1);
  UINT8 *p=(VOID *)out;for(unsigned i=0;i<8;i++) require(p[i]==path[i]);
  require(p[8]==4&&p[9]==6&&p[10]==20&&p[11]==0);
  for(unsigned i=0;i<16;i++) require(p[12+i]==((UINT8 *)&UfsGuid)[i]);
  require(p[28]==0x7f&&p[29]==0xff&&p[30]==4&&p[31]==0);free(out);
  unsigned tests=1;
  path[2]=0;require(ufs_path((EFI_HANDLE)1)==NULL);tests++;
  path[2]=3;require(ufs_path((EFI_HANDLE)1)==NULL);tests++;
  path[2]=0xff;path[3]=0xff;require(ufs_path((EFI_HANDLE)1)==NULL);tests++;
  path[2]=8;path[3]=0;path[9]=1;require(ufs_path((EFI_HANDLE)1)==NULL);tests++;
  path[9]=0xff;path[10]=5;require(ufs_path((EFI_HANDLE)1)==NULL);tests++;
  path[10]=4;path[0]=4;path[1]=6;require(ufs_path((EFI_HANDLE)1)==NULL);tests++;
  TestPath=NULL;require(ufs_path((EFI_HANDLE)1)==NULL);tests++;
  TestPath=(VOID *)path;require(ufs_path((EFI_HANDLE)2)==NULL);tests++;
  memset(path,0,sizeof(path));for(unsigned i=0;i<4000;i+=4) {path[i]=1;path[i+1]=4;path[i+2]=4;}
  require(ufs_path((EFI_HANDLE)1)==NULL);tests++;
  require(Allocations==1);printf("FV path tests passed: %u; malformed paths never allocated\n",tests);return 0;
}
