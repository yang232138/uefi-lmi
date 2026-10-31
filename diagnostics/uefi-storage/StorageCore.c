/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Bounded metadata reader. The only storage callback reads bytes.
 * No controller programming, filesystem mounting or block writes.
 */
#include "StorageCore.h"
#include "samples.h"
static uint8_t Header[4096], Entries[131072], Block[4096];
static uint32_t le32(const uint8_t *p) {
  return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static uint64_t le64(const uint8_t *p) { return le32(p)|(uint64_t)le32(p+4)<<32; }
static int eq(const void *a,const void *b,size_t n) {
  const uint8_t *x=a,*y=b; while(n--) if(*x++!=*y++) return 0; return 1;
}
static void cp(void *a,const void *b,size_t n) {
  uint8_t *x=a; const uint8_t *y=b; while(n--) *x++=*y++;
}
static int readat(RO_DISK *d,uint64_t at,size_t n,void *b) {
  if(at>d->bytes || (uint64_t)n>d->bytes-at) return 0;
  return d->read(d->ctx,at,n,b)==0;
}
static void logline(RO_LOG log,const char *s) { if(log) log(s); }
static void logdigest(RO_LOG log,const uint8_t h[32]) {
  static const char hex[]="0123456789abcdef";char s[72]="sha256=";
  for(unsigned i=0;i<32;i++) {s[7+i*2]=hex[h[i]>>4];s[8+i*2]=hex[h[i]&15];}
  s[71]=0;logline(log,s);
}
uint32_t ro_crc32(const void *buf,size_t n) {
  const uint8_t *p=buf; uint32_t c=~0u;
  while(n--) { c^=*p++; for(unsigned i=0;i<8;i++) c=(c>>1)^(0xedb88320u & (0u-(c&1))); }
  return ~c;
}
static const uint32_t K[64]={
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static uint32_t rr(uint32_t x,unsigned n) { return x>>n|x<<(32-n); }
static void compress(uint32_t h[8],const uint8_t p[64]) {
  uint32_t w[64]; for(unsigned i=0;i<16;i++) w[i]=(uint32_t)p[i*4]<<24|(uint32_t)p[i*4+1]<<16|(uint32_t)p[i*4+2]<<8|p[i*4+3];
  for(unsigned i=16;i<64;i++) {
    uint32_t a=w[i-15],b=w[i-2];
    w[i]=w[i-16]+(rr(a,7)^rr(a,18)^(a>>3))+w[i-7]+(rr(b,17)^rr(b,19)^(b>>10));
  }
  uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],v=h[7];
  for(unsigned i=0;i<64;i++) {
    uint32_t t=v+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+K[i]+w[i];
    uint32_t u=(rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c));
    v=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;
  }
  h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=v;
}
void ro_sha256(const void *data,size_t n,uint8_t out[32]) {
  const uint8_t *p=data; uint64_t bits=(uint64_t)n*8;
  uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  while(n>=64) { compress(h,p);p+=64;n-=64; }
  uint8_t tail[128]; for(unsigned i=0;i<128;i++) tail[i]=0;
  cp(tail,p,n);tail[n]=128; unsigned total=n<56?64:128;
  for(unsigned i=0;i<8;i++) tail[total-1-i]=(uint8_t)(bits>>(i*8));
  compress(h,tail);if(total==128) compress(h,tail+64);
  for(unsigned i=0;i<8;i++) for(unsigned j=0;j<4;j++) out[i*4+j]=(uint8_t)(h[i]>>(24-j*8));
}
int ro_apfs_checksum(const void *data,size_t n) {
  const uint8_t *p=data; uint64_t a=0,b=0;
  if(n!=4096 || le64(p)==0 || le64(p)==UINT64_MAX) return 0;
  for(size_t i=8;i<n;i+=4) {a+=le32(p+i);b+=a;}
  a+=le32(p);b+=a;a+=le32(p+4);b+=a;
  return a%0xffffffffu==0 && b%0xffffffffu==0;
}
/* mode 0: physical GPT 'userdata'; mode 1: exactly one Apple APFS partition. */
int ro_gpt(RO_DISK *d,uint32_t bs,int mode,RO_PART *part,RO_LOG log) {
  static const uint8_t apfs[16]={0xef,0x57,0x34,0x7c,0,0,0xaa,0x11,0xaa,0x11,0,0x30,0x65,0x43,0xec,0xac};
  if(bs<512 || bs>4096 || (bs&(bs-1)) || d->bytes/bs<3 || !readat(d,bs,bs,Header)) return 0;
  if(!eq(Header,"EFI PART",8) || le32(Header+8)!=0x10000 || le64(Header+24)!=1) return 0;
  uint32_t hs=le32(Header+12),crc=le32(Header+16);
  if(hs<92 || hs>bs) return 0;
  for(unsigned i=16;i<20;i++) Header[i]=0;
  if(ro_crc32(Header,hs)!=crc) {logline(log,"GPT header CRC FAIL");return 0;}
  uint64_t first=le64(Header+40),last=le64(Header+48),elba=le64(Header+72);
  uint32_t count=le32(Header+80),es=le32(Header+84),ec=le32(Header+88);
  if(first>last || last>=d->bytes/bs || le64(Header+32)>=d->bytes/bs || elba<2 || elba>=first) return 0;
  if(!count || count>1024 || es<128 || es>512 || es%8 || (uint64_t)count*es>sizeof(Entries)) return 0;
  size_t len=(size_t)count*es;
  if(len>(first-elba)*(uint64_t)bs || !readat(d,elba*(uint64_t)bs,len,Entries)) return 0;
  if(ro_crc32(Entries,len)!=ec) {logline(log,"GPT entries CRC FAIL");return 0;}
  unsigned matches=0;
  for(unsigned i=0;i<count;i++) {
    const uint8_t *e=Entries+(size_t)i*es; int want=0;
    if(mode==1) want=eq(e,apfs,16);
    else {
      static const char name[]="userdata";want=1;
      for(unsigned k=0;k<sizeof(name);k++) if(e[56+k*2]!=(uint8_t)name[k] || e[57+k*2]!=0) want=0;
      uint8_t nonzero=0;for(unsigned k=0;k<16;k++) nonzero|=e[k];if(!nonzero) want=0;
    }
    if(!want) continue;
    uint64_t lo=le64(e+32),hi=le64(e+40);
    if(lo<first || lo>hi || hi>last) return 0;
    matches++;part->offset=lo*(uint64_t)bs;part->bytes=(hi-lo+1)*(uint64_t)bs;
  }
  if(matches!=1) return 0;
  logline(log,mode?"OS GPT header + entries CRC PASS":"Physical GPT + userdata PASS");return 1;
}
typedef struct { RO_DISK *parent;uint64_t base; } SUB;
static int subread(void *ctx,uint64_t at,size_t n,void *b) {
  SUB *s=ctx;return readat(s->parent,s->base+at,n,b)?0:-1;
}
static int fail(RO_RESULT *r,const char *s,RO_LOG log) {
  size_t i=0;while(i+1<sizeof(r->failed)&&s[i]) {r->failed[i]=s[i];i++;}r->failed[i]=0;logline(log,s);return 0;
}
int ro_verify_userdata(RO_DISK *d,RO_RESULT *r,RO_LOG log) {
  uint8_t digest[32];
  if(!readat(d,0,4096,Block)) return fail(r,"Manifest READ FAIL",log);
  if(!eq(Block,"SHNGROOT",8) || le32(Block+8)!=1 || le32(Block+12)!=2 || le64(Block+16)>d->bytes) return fail(r,"Manifest format/bounds FAIL",log);
  ro_sha256(Block,4064,digest);
  if(!eq(digest,Block+4064,32)) return fail(r,"Manifest self hash FAIL",log);
  ro_sha256(Block,4096,digest);
  logdigest(log,digest);
  if(!eq(digest,Samples[0].sha,32)) return fail(r,"Manifest differs from supplied image",log);
  uint64_t offsets[2],sizes[2];
  for(unsigned i=0;i<2;i++) {
    const uint8_t *e=Block+24+i*128;offsets[i]=le64(e+32);sizes[i]=le64(e+40);
    if(offsets[i]<0x100000 || offsets[i]%0x100000 || !sizes[i] || offsets[i]>d->bytes || sizes[i]>d->bytes-offsets[i] || le32(e+48)!=512 || le32(e+52)!=1) return fail(r,"Window bounds/attributes FAIL",log);
  }
  if(offsets[0]+sizes[0]>offsets[1]) return fail(r,"Overlapping windows FAIL",log);
  r->manifest=1;logline(log,"SHNGROOT self hash + exact sample PASS");
  SUB sub={d,offsets[0]};RO_DISK os={subread,&sub,sizes[0]};RO_PART ap={0,0};
  if(!ro_gpt(&os,512,1,&ap,log)) return fail(r,"OS GPT FAIL",log);
  r->os_gpt=1;
  for(unsigned i=1;i<SAMPLE_COUNT;i++) {
    const SAMPLE *s=&Samples[i];
    if(s->bytes>sizeof(Block) || !readat(d,s->offset,s->bytes,Block)) return fail(r,s->name,log);
    ro_sha256(Block,s->bytes,digest);
    logdigest(log,digest);
    if(!eq(digest,s->sha,32)) return fail(r,s->name,log);
    if(s->kind && (!ro_apfs_checksum(Block,s->bytes) || !eq(Block+32,s->kind==1?"NXSB":"APSB",4))) return fail(r,"APFS sample format/checksum FAIL",log);
    if(s->kind==1 && (le32(Block+36)!=4096 || le64(Block+40)>sizes[i>=4?1:0]/4096)) return fail(r,"APFS container bounds FAIL",log);
    if(i==2) {if(s->offset!=offsets[0]+ap.offset) return fail(r,"OS APFS offset mismatch",log);r->os_nx=1;}
    if(i==3) {if(!eq(Block+0xf0,RootUuid,16)) return fail(r,"Root UUID sample FAIL",log);r->root_sample=1;}
    if(i==4) r->system_nx=1;
    if(i==5) r->system_volume=1;
    logline(log,s->name);
  }
  r->matched=1;logline(log,"METADATA SAMPLES MATCH (not full disk hash)");return 1;
}
