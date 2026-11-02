/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#define LMI_LOG_ROWS 22U
#define LMI_LOG_COLUMNS 68U
static UINTN LogLine(const LMI_SERIAL_LOG *log,UINTN at,char *out) {
  UINTN n=0;
  while(at<log->Count && n<LMI_LOG_COLUMNS) {
    UINT8 c=log->Bytes[at++];
    if(c=='\r') continue;
    if(c=='\n') break;
    out[n++]=(c>=32 && c<=126)?(char)c:' ';
  }
  out[n]=0;return at;
}
static UINTN LogPages(const LMI_SERIAL_LOG *log) {
  UINTN rows=0,at=0;char out[LMI_LOG_COLUMNS+1];
  if(!log) return 1;
  while(at<log->Count) {at=LogLine(log,at,out);rows++;}
  return rows?(rows+LMI_LOG_ROWS-1)/LMI_LOG_ROWS:1;
}
