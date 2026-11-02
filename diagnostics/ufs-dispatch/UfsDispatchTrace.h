/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef LMI_UFS_DISPATCH_TRACE_H
#define LMI_UFS_DISPATCH_TRACE_H

#define LMI_TRACE_GUID {0x4c45f3a1,0xcf78,0x4ba1,{0xb4,0x96,0x54,0xaa,0x56,0x68,0x9c,0x19}}
#define LMI_UFS_GUID {0x0d35cd8e,0x97ea,0x4f9a,{0x96,0xaf,0x0f,0x0d,0x89,0xf7,0x65,0x67}}
#define LMI_TRACE_SIGNATURE 0x44534655U
#define LMI_TRACE_CAPACITY 128U
#define LMI_TRACE_VERSION 1U

enum {
  LmiTraceInit=1, LmiTraceDiscovered, LmiTraceDependency,
  LmiTraceScheduled, LmiTraceLoadBegin, LmiTraceLoadEnd,
  LmiTraceEntryBegin, LmiTraceEntryEnd, LmiTraceDispatchEnd,
  LmiTraceApriori
};

typedef struct {
  UINT64 Sequence;
  UINT64 Stage;
  UINT64 Status;
  UINT64 Flags;
} LMI_TRACE_RECORD;

typedef struct {
  UINT32 Signature;
  UINT32 Version;
  UINT32 Size;
  UINT32 Capacity;
  UINT32 Count;
  UINT32 Dropped;
  EFI_GUID Target;
  LMI_TRACE_RECORD Records[LMI_TRACE_CAPACITY];
} LMI_TRACE_TABLE;

#endif
