"""Exercise the actual C reader using sparse real metadata and damaged inputs."""
from pathlib import Path
import base64,ctypes as C,hashlib,json,os,struct,subprocess,sys,zlib
root=Path(__file__).resolve().parent
libpath=root/('StorageCore.dll' if os.name=='nt' else 'StorageCore.so')
if not libpath.exists():
    compiler=os.environ.get('CC','cc')
    subprocess.run([compiler,'-shared','-fPIC','-O2','-Wall','-Wextra','-Werror',str(root/'StorageCore.c'),'-o',str(libpath)],check=True)
lib=C.CDLL(str(libpath))
READ=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_size_t,C.c_void_p)
LOG=C.CFUNCTYPE(None,C.c_char_p)
class Disk(C.Structure): _fields_=[('read',READ),('ctx',C.c_void_p),('bytes',C.c_uint64)]
class Part(C.Structure): _fields_=[('offset',C.c_uint64),('bytes',C.c_uint64)]
class Result(C.Structure):
    _fields_=[(x,C.c_int) for x in ['manifest','os_gpt','os_nx','root_sample','system_nx','system_volume','matched']]+[('userdata_offset',C.c_uint64),('userdata_bytes',C.c_uint64),('failed',C.c_char*80)]
lib.ro_gpt.argtypes=[C.POINTER(Disk),C.c_uint32,C.c_int,C.POINTER(Part),LOG]
lib.ro_verify_userdata.argtypes=[C.POINTER(Disk),C.POINTER(Result),LOG]
lib.ro_sha256.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p]
lib.ro_crc32.argtypes=[C.c_void_p,C.c_size_t];lib.ro_crc32.restype=C.c_uint32
lib.ro_apfs_checksum.argtypes=[C.c_void_p,C.c_size_t]
fixture=json.loads((root/'metadata-fixture.json').read_text())
original=[(x['offset'],base64.b64decode(x['data'])) for x in fixture['segments']]
tests=[]
def check(label,condition):
    assert condition,label
    tests.append(label)
for n in [0,1,3,55,56,63,64,65,127,128,4096,5000]:
    b=bytes((i*37+11)%256 for i in range(n));out=C.create_string_buffer(32)
    lib.ro_sha256(b,len(b),out);check('sha256 '+str(n),out.raw==hashlib.sha256(b).digest())
    check('crc32 '+str(n),lib.ro_crc32(b,len(b))==zlib.crc32(b))
def reader(segments,size,fail=False):
    reads=[]
    @READ
    def read(ctx,at,n,dest):
        reads.append((at,n))
        if fail or at>size or n>size-at or n>131072: return -1
        b=bytearray(n)
        for start,data in segments:
            lo=max(at,start);hi=min(at+n,start+len(data))
            if lo<hi: b[lo-at:hi-at]=data[lo-start:hi-start]
        C.memmove(dest,bytes(b),n);return 0
    return Disk(read,None,size),read,reads
messages=[]
@LOG
def log(s): messages.append(s.decode())
d,keep,reads=reader(original,fixture['bytes']);r=Result()
check('real six metadata samples',lib.ro_verify_userdata(C.byref(d),C.byref(r),log)==1)
check('all stages reached',all(getattr(r,x)==1 for x in ['manifest','os_gpt','os_nx','root_sample','system_nx','system_volume','matched']))
check('bounded sampled I/O',sum(n for _,n in reads)<65536)
for start,b in original:
    if b[32:36] in (b'NXSB',b'APSB'):
        check('valid APFS checksum '+str(start),lib.ro_apfs_checksum(b,len(b))==1)
        bad=bytearray(b);bad[80]^=1
        check('damaged APFS checksum '+str(start),lib.ro_apfs_checksum(bytes(bad),len(bad))==0)
for index in [0,2,3,4,5]:
    altered=list(original);at,b=altered[index];bad=bytearray(b);bad[len(b)//2]^=1;altered[index]=(at,bytes(bad))
    d,keep,_=reader(altered,fixture['bytes']);r=Result()
    check('reject altered sample '+str(index),lib.ro_verify_userdata(C.byref(d),C.byref(r),log)==0 and not r.matched)
d,keep,_=reader(original,fixture['bytes'],fail=True);r=Result()
check('read failure does not pass',lib.ro_verify_userdata(C.byref(d),C.byref(r),log)==0 and not r.matched)
d,keep,_=reader(original,4096);r=Result()
check('reject short partition',lib.ro_verify_userdata(C.byref(d),C.byref(r),log)==0)
def gpt(bs):
    lo=2048;blocks=(fixture['bytes']+bs-1)//bs;total=lo+blocks+2048
    entries=bytearray(128*128)
    entries[:16]=bytes.fromhex('a2a0d0ebe5b9334487c068b6b72699c7')
    entries[16:32]=bytes(range(1,17));struct.pack_into('<QQ',entries,32,lo,lo+blocks-1)
    name='userdata'.encode('utf-16-le');entries[56:56+len(name)]=name
    h=bytearray(bs);h[:8]=b'EFI PART';struct.pack_into('<III',h,8,0x10000,92,0)
    struct.pack_into('<QQQQ',h,24,1,total-1,34,total-34)
    struct.pack_into('<QIII',h,72,2,128,128,zlib.crc32(entries))
    struct.pack_into('<I',h,16,zlib.crc32(h[:92]))
    return lo*bs,total*bs,bytes(h),bytes(entries)
for bs in [512,4096]:
    base,total,h,entries=gpt(bs)
    segments=[(bs,h),(bs*2,entries)]+[(base+at,b) for at,b in original]
    d,keep,reads=reader(segments,total);p=Part()
    check('outer GPT blocksize '+str(bs),lib.ro_gpt(C.byref(d),bs,0,C.byref(p),log)==1 and p.offset==base and p.bytes==fixture['bytes'])
    @READ
    def partread(ctx,at,n,dest): return keep(None,base+at,n,dest)
    part=Disk(partread,None,p.bytes);r=Result()
    check('disk to partition to nested OS '+str(bs),lib.ro_verify_userdata(C.byref(part),C.byref(r),log)==1)
    damaged=bytearray(h);damaged[16]^=1
    bad,handle,_=reader([(bs,bytes(damaged)),(bs*2,entries)],total);p=Part()
    check('reject header CRC '+str(bs),lib.ro_gpt(C.byref(bad),bs,0,C.byref(p),log)==0)
    damaged=bytearray(entries);damaged[80]^=1
    bad,handle,_=reader([(bs,h),(bs*2,bytes(damaged))],total)
    check('reject entries CRC '+str(bs),lib.ro_gpt(C.byref(bad),bs,0,C.byref(p),log)==0)
    # Recompute the header CRC so the oversized entry count reaches its bounds check.
    damaged=bytearray(h);struct.pack_into('<I',damaged,80,0xffffffff);struct.pack_into('<I',damaged,16,0)
    struct.pack_into('<I',damaged,16,zlib.crc32(damaged[:92]))
    bad,handle,attempts=reader([(bs,bytes(damaged))],total)
    check('reject oversized table '+str(bs),lib.ro_gpt(C.byref(bad),bs,0,C.byref(p),log)==0 and len(attempts)==1)
(root/'core-test-results.json').write_text(json.dumps(dict(passed=len(tests),tests=tests,real_metadata_fixture=True,phone_tested=False),indent=2)+'\n')
print(json.dumps({'passed':len(tests),'real_metadata_fixture':True,'phone_tested':False}))
