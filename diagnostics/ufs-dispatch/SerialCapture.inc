/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Preserve every underlying serial call and its return value. No hardware
 * calls added; copy attempted bytes only while the target entry is running.
 */
#include "UfsSerialLog.h"
STATIC LMI_SERIAL_LOG mLmiSerialLog = {
  LMI_LOG_SIGNATURE,1,sizeof(LMI_SERIAL_LOG),LMI_LOG_CAPACITY,0,0,0,0,{0}
};
STATIC UINTN EFIAPI
LmiSerialWrite (UINT8 *Buffer, UINTN NumberOfBytes)
{
  UINTN I, Available, Copy;
  if (mLmiSerialLog.Enabled && Buffer != NULL) {
    if (mLmiSerialLog.Calls != MAX_UINT32) mLmiSerialLog.Calls++;
    Available = LMI_LOG_CAPACITY - mLmiSerialLog.Count;
    Copy = NumberOfBytes < Available ? NumberOfBytes : Available;
    for (I = 0; I < Copy; I++) mLmiSerialLog.Bytes[mLmiSerialLog.Count + I] = Buffer[I];
    mLmiSerialLog.Count += (UINT32)Copy;
    if (NumberOfBytes - Copy > MAX_UINT32 - mLmiSerialLog.Dropped) {
      mLmiSerialLog.Dropped = MAX_UINT32;
    } else {
      mLmiSerialLog.Dropped += (UINT32)(NumberOfBytes - Copy);
    }
  }
  return SerialPortWrite (Buffer, NumberOfBytes);
}
