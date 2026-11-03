/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef LMI_IOMMU_OBSERVE_H
#define LMI_IOMMU_OBSERVE_H
#define LMI_IOMMU_GUID {0x3ecb3454,0xd69b,0x4a95,{0x87,0xe1,0xaa,0x64,0x0e,0x49,0x2c,0x23}}
#define LMI_IOMMU_SIGNATURE 0x314c4c41434d4d49ULL
#define LMI_IOMMU_CAPACITY 24
typedef struct {
  UINT32 Kind, Completed, ReturnCode, Reserved;
  UINT64 Domain, Argument, Arid, Flags;
} LMI_IOMMU_RECORD;
typedef struct {
  UINT64 Signature;
  UINT32 Version, Size, Count, Dropped;
  UINT64 Protocol, Functions;
  UINT32 Located, Wrapped;
  LMI_IOMMU_RECORD Records[LMI_IOMMU_CAPACITY];
} LMI_IOMMU_TABLE;
#endif
