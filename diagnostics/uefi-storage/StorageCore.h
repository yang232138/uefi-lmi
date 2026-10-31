#ifndef STORAGE_CORE_H
#define STORAGE_CORE_H
#include <stdint.h>
#include <stddef.h>
typedef int (*RO_READ)(void *, uint64_t, size_t, void *);
typedef void (*RO_LOG)(const char *);
typedef struct { RO_READ read; void *ctx; uint64_t bytes; } RO_DISK;
typedef struct { uint64_t offset, bytes; } RO_PART;
typedef struct {
  int manifest, os_gpt, os_nx, root_sample, system_nx, system_volume, matched;
  uint64_t userdata_offset, userdata_bytes;
  char failed[80];
} RO_RESULT;
uint32_t ro_crc32(const void *, size_t);
void ro_sha256(const void *, size_t, uint8_t[32]);
int ro_apfs_checksum(const void *, size_t);
int ro_gpt(RO_DISK *, uint32_t, int, RO_PART *, RO_LOG);
int ro_verify_userdata(RO_DISK *, RO_RESULT *, RO_LOG);
#endif
