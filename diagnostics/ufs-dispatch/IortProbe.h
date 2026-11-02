#ifndef LMI_IORT_PROBE_H
#define LMI_IORT_PROBE_H
#define LMI_IORT_PROBE_GUID {0xc7eb997a,0xba73,0x4f89,{0xa8,0x1c,0x7d,0x62,0x9e,0xfa,0x25,0x04}}
#define LMI_IORT_PROBE_SIGNATURE 0x524f494cU
#define LMI_IORT_PROBE_REGIONS 4U
#define LMI_IORT_PROBE_NODES 12U
typedef struct {
  CHAR8 Name[32];
  UINT64 LookupStatus, Address, Length, Scanned;
  UINT32 ValidFdt, Skipped;
  INT32 IortOffset, UfsOffset, CacheLength;
  UINT32 CacheValue;
} LMI_IORT_REGION;
typedef struct {
  UINT32 Signature, Version, Size, ReadOnly;
  LMI_IORT_REGION Regions[LMI_IORT_PROBE_REGIONS];
  UINT32 NodeCount, NodesDropped;
  CHAR8 NodeNames[LMI_IORT_PROBE_NODES][64];
} LMI_IORT_PROBE;
#endif
