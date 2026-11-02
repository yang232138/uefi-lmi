/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef LMI_UFS_SERIAL_LOG_H
#define LMI_UFS_SERIAL_LOG_H
#define LMI_LOG_GUID {0x66db9cba,0x7bb9,0x441f,{0x99,0x63,0x7f,0xf7,0x30,0x52,0x18,0x06}}
#define LMI_LOG_SIGNATURE 0x474c4655U
#define LMI_LOG_CAPACITY 32768U
#define LMI_LOG_LIB_NAME "LMI UFS Serial Log v1"
typedef struct {
  UINT32 Signature,Version,Size,Capacity;
  volatile UINT32 Enabled,Count,Dropped,Calls;
  UINT8 Bytes[LMI_LOG_CAPACITY];
} LMI_SERIAL_LOG;
#endif
