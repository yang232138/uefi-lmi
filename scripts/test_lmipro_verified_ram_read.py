"""Exercise the exact kernel read primitive with real RSA and current signed image."""
from pathlib import Path
import argparse,ctypes,hashlib,json,os,struct,subprocess,sys
ap=argparse.ArgumentParser();ap.add_argument('--cc',required=True);ap.add_argument('--openssl-prefix',type=Path,required=True)
ap.add_argument('--out',type=Path,required=True);ap.add_argument('--kit',type=Path,required=True)
ap.add_argument('--policy',type=Path);ap.add_argument('--seed',type=Path);ap.add_argument('--implementation-dir',type=Path)
a=ap.parse_args();p=Path(__file__).parent;out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
source=a.policy or p.parent/'root-crypto/policy-artifact/root-policy'
implementation=a.implementation_dir or p
if os.name=='nt':dll_path=os.add_dll_directory(str(a.openssl_prefix/'bin'))
library=out/('read-integrity.dll' if os.name=='nt' else 'read-integrity.dylib')
provider=out/'host_provider.c'
provider.write_text('#include "openssl_provider.c"\nconst struct vr_crypto *lr_host_crypto(void) { return &provider; }\n')
command=[a.cc,'-std=c11','-Wall','-Wextra','-Werror','-shared' if os.name=='nt' else '-dynamiclib',
 '-I',str(a.kit/'include'),'-I',str(a.kit/'tests'),'-I',str(a.openssl_prefix/'include'),'-I',str(implementation),
 str(a.kit/'src/verified_root.c'),str(provider),str(implementation/'LmiproVerifiedRamIo.c'),
 '-L',str(a.openssl_prefix/'lib'),'-lcrypto','-o',str(library)]
subprocess.run(command,check=True)
class View(ctypes.Structure):
 _fields_=[('hashes',ctypes.c_void_p),('image_bytes',ctypes.c_uint64),('block_count',ctypes.c_uint64),('generation',ctypes.c_uint64),('uuid',ctypes.c_uint8*16),('hash',ctypes.c_uint8*32)]
HASH=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p)
RSA=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p)
class Crypto(ctypes.Structure):_fields_=[('sha',HASH),('rsa',RSA)]
LOAD=ctypes.CFUNCTYPE(ctypes.c_int,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_size_t)
EMIT=ctypes.CFUNCTYPE(ctypes.c_size_t,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_size_t)
class Io(ctypes.Structure):_fields_=[('context',ctypes.c_void_p),('load',LOAD),('emit',EMIT)]
lib=ctypes.CDLL(str(library))
lib.vr_host_open.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_uint64,ctypes.POINTER(View)]
lib.lmipro_verified_ram_read.argtypes=[ctypes.POINTER(View),ctypes.POINTER(Crypto),ctypes.c_uint64,ctypes.c_size_t,ctypes.POINTER(Io),ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint64),ctypes.POINTER(ctypes.c_uint64)]
encoded=ctypes.create_string_buffer((source/'manifest.bin').read_bytes());key=ctypes.create_string_buffer((source/'trusted-key.bin').read_bytes());view=View()
assert hashlib.sha256(encoded.raw[:-1]).hexdigest()=='8d8836c00d21b290c13b87ce9913d9f93d0cbf3a88d8d156f2511af7f031e229'
assert hashlib.sha256(key.raw[:-1]).hexdigest()=='95b218c864db0787a303ec5540c51660e8ed2348f43157ae683f349be2cf5105'
assert lib.vr_host_open(encoded,len(encoded)-1,key,1,ctypes.byref(view))==0
assert view.image_bytes==268394496 and view.block_count==65526
# Expose the actual unchanged official static OpenSSL provider through a getter.
lib.lr_host_crypto.restype=ctypes.POINTER(Crypto)
crypto=lib.lr_host_crypto()
seed=(a.seed or p.parent/'ram-root/seed-artifact/test-root.dbrdisk').read_bytes()
assert hashlib.sha256(seed).hexdigest()=='64a0b51fcdd7b026675633d42321fe594d93a7d4b27c9c4c9755201f3b743676'
magic,version,page,logical,count=struct.unpack_from('<8sIIQQ',seed)
assert (magic,version,page,logical)==(b'DBRDISK1',1,4096,view.image_bytes)
raw=bytearray(logical);cursor=32+16*count
for i in range(count):
 offset,length=struct.unpack_from('<QQ',seed,32+16*i);raw[offset:offset+length]=seed[cursor:cursor+length];cursor+=length
assert cursor==len(seed) and hashlib.sha256(raw).digest()==bytes(view.hash)
checks=[]
def request(offset,length,*,tamper=None,load_fail=None,short_emit=False,expected=0,prefix=None):
 destination=bytearray(b'\xa5'*length);actual=ctypes.c_uint64();blocks=ctypes.c_uint64();scratch=(ctypes.c_uint8*4096)();calls=[]
 @LOAD
 def load(context,base,target,size):
  calls.append(base)
  if base==load_fail:return 0
  value=bytearray(raw[base:base+size])
  if base==tamper:value[0]^=1
  ctypes.memmove(target,bytes(value),len(value));return 1
 @EMIT
 def emit(context,at,source,size):
  n=size//2 if short_emit else size
  destination[at:at+n]=ctypes.string_at(source,n);return n
 io=Io(None,load,emit)
 status=lib.lmipro_verified_ram_read(ctypes.byref(view),crypto,offset,length,ctypes.byref(io),scratch,ctypes.byref(actual),ctypes.byref(blocks))
 assert status==expected,(status,expected)
 if expected==0:assert actual.value==length and destination==raw[offset:offset+length]
 if prefix is not None:
  assert actual.value==prefix and destination[:prefix]==raw[offset:offset+prefix]
  assert destination[prefix:]==b'\xa5'*(length-prefix),'Unverified bytes escaped to consumer'
 return actual.value,blocks.value,calls
request(0,4096);request(123,8192);request(logical-17,17)
checks.append('full, unaligned cross-block and exact final-tail reads match actual signed root')
request(0,4096,tamper=0,expected=3,prefix=0)
request(0,8192,tamper=4096,expected=3,prefix=4096)
checks.append('first/later block mutation refused before any unverified byte is published')
request(0,4096,load_fail=0,expected=2,prefix=0)
request(0,4096,short_emit=True,expected=4,prefix=2048)
checks.append('source failure and short consumer copy fail with exact verified prefix accounting')
request(logical,1,expected=1,prefix=0);request((1<<64)-1,1,expected=1,prefix=0)
request(logical-1,2,expected=1,prefix=0)
checks.append('outside/overflow/cross-end requests refused before source access')
report=dict(real_current_rsa_policy_opened=True,exact_signed_root_sha256=hashlib.sha256(raw).hexdigest(),
 source_sha256=hashlib.sha256((implementation/'LmiproVerifiedRamIo.c').read_bytes()).hexdigest(),checks=checks,
 unverified_bytes_published=False,kernel_execution=False,hardware_tested=False)
(out/'read-integrity-checks.json').write_text(json.dumps(report,indent=2)+'\n')
print('PASS:',len(checks),'read-integrity groups against real signed RAM image; host only')
