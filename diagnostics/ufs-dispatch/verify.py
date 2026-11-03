"""Independent, portable boot/FAT/PE verifier; no external tools or device access."""
from pathlib import Path
import argparse,hashlib,json,struct,tomllib,zlib
HISTORICAL_FD_SHA='720481eb15e6cb3a6552c717ee6e912649a9c81eef18c95ab00dff7627530ee6'
SHIM_SHA='fca5c1e7fd9b455c27c4039a66c27792c0f475a515b0e4f3bf0a088fcf256195'
DTB_SHA='38027bacdd3535776d83801b53e8eb5e41f2facb9e7d2fe72b412b26b3f7f033'
def sha(b): return hashlib.sha256(b).hexdigest()
def pe(b):
    assert b[:2]==b'MZ';p=struct.unpack_from('<I',b,60)[0]
    assert b[p:p+4]==b'PE\0\0'
    machine,sections=struct.unpack_from('<HH',b,p+4);osize=struct.unpack_from('<H',b,p+20)[0];o=p+24
    assert machine==0xaa64 and struct.unpack_from('<H',b,o)[0]==0x20b
    entry=struct.unpack_from('<I',b,o+16)[0]
    assert struct.unpack_from('<H',b,o+68)[0]==10
    assert struct.unpack_from('<II',b,o+120)==(0,0), 'unexpected imports'
    assert struct.unpack_from('<II',b,o+144)==(0,0), 'unexpected certificate'
    reloc,size=struct.unpack_from('<II',b,o+152);assert reloc and size>=8
    found=False;rfound=False
    for n in range(sections):
        s=o+osize+40*n;vs,va,raw,at=struct.unpack_from('<IIII',b,s+8);flags=struct.unpack_from('<I',b,s+36)[0]
        assert at+raw<=len(b)
        if va<=entry<va+min(vs,raw): assert flags&0x20000000;found=True
        if va<=reloc and reloc+size<=va+raw: rfound=True
    assert found and rfound
    return dict(machine='ARM64',subsystem='EFI_APPLICATION',entry_rva=hex(entry),relocations=True,imports=False,sha256=sha(b),bytes=len(b))
class Fat:
    def __init__(self,b):
        self.b=b;assert b[510:512]==b'\x55\xaa'
        self.bs=struct.unpack_from('<H',b,11)[0];self.spc=b[13];self.res=struct.unpack_from('<H',b,14)[0];self.nfat=b[16]
        rootentries=struct.unpack_from('<H',b,17)[0];f16=struct.unpack_from('<H',b,22)[0]
        assert self.bs==512 and self.spc and not rootentries and not f16,'expected FAT32'
        self.fsz=struct.unpack_from('<I',b,36)[0];self.root=struct.unpack_from('<I',b,44)[0]
        assert self.nfat in (1,2) and self.res and self.fsz
        total=struct.unpack_from('<I',b,32)[0];assert total*self.bs==len(b)
        self.data=(self.res+self.nfat*self.fsz)*self.bs
    def chain(self,c):
        seen=set();parts=[]
        while c<0xffffff8:
            assert 2<=c<0xffffff0 and c not in seen and len(seen)<131072
            seen.add(c);at=self.data+(c-2)*self.bs*self.spc;end=at+self.bs*self.spc
            assert end<=len(self.b);parts.append(self.b[at:end]);fatat=self.res*self.bs+c*4
            assert fatat+4<=(self.res+self.fsz)*self.bs
            c=struct.unpack_from('<I',self.b,fatat)[0]&0xfffffff
        return b''.join(parts)
    def read(self,path):
        c=self.root;parts=path.strip('/').split('/')
        for index,name in enumerate(parts):
            directory=self.chain(c);found=None;lfn={}
            for at in range(0,len(directory),32):
                e=directory[at:at+32]
                if not e or e[0]==0: break
                if e[0]==0xe5: lfn={};continue
                if e[11]==15:
                    raw=e[1:11]+e[14:26]+e[28:32];lfn[e[0]&31]=raw.decode('utf-16-le');continue
                short=e[:8].decode('ascii').rstrip();ext=e[8:11].decode('ascii').rstrip();short+=('.'+ext) if ext else ''
                long=''.join(lfn[k] for k in sorted(lfn)).split('\0')[0].rstrip('\uffff');lfn={}
                if name.casefold() in (short.casefold(),long.casefold()): found=e;break
            assert found is not None,'FAT file missing: '+path
            c=(struct.unpack_from('<H',found,20)[0]<<16)|struct.unpack_from('<H',found,26)[0]
            if index+1<len(parts): assert found[11]&16
        size=struct.unpack_from('<I',found,28)[0];return self.chain(c)[:size]

def verify(folder, source=None):
    folder=Path(folder);b=(folder/'boot.img').read_bytes()
    assert b[:8]==b'ANDROID!'
    ks,ka,rs,ra,ss,sa,tags,page,version,_=struct.unpack_from('<10I',b,8)
    assert page==4096 and version==1 and rs==ss==0
    assert ka==0x8000 and page+ks<=len(b) and len(b)%page==0
    d=zlib.decompressobj(31);raw=d.decompress(b[page:page+ks]);assert d.eof
    dtb=d.unused_data;assert sha(dtb)==DTB_SHA
    assert struct.unpack_from('>I',dtb,4)[0]==len(dtb)
    shim=raw[:368];fd=raw[368:368+0x300000];pos=368+0x300000
    assert sha(shim)==SHIM_SHA and len(fd)==0x300000
    assert sha(fd)!=HISTORICAL_FD_SHA, 'Expected rebuilt instrumented firmware'
    assert fd==(folder/'SILICIUM_UEFI.fd').read_bytes()
    assert raw[pos:pos+4]==b'XNUP'
    n=struct.unpack_from('<I',raw,pos+4)[0];payload=raw[pos+8:]
    assert len(payload)==n==64*1024*1024
    fat=Fat(payload);cfg=fat.read('EFI/UniXNU/unixnu.toml')
    app=fat.read('EFI/UniXNU/Payloads/TraceView.efi')
    assert app==(folder/'TraceView.efi').read_bytes()
    config=tomllib.loads(cfg.decode())
    assert config['boot']['connect_all'] is False
    assert len(config['entry'])==1 and config['entry'][0]['type']=='efi'
    assert config['entry'][0]['id']==config['boot']['default']=='ufs-dispatch'
    assert config['entry'][0]['path']=='Payloads/TraceView.efi'
    if source: assert cfg==(Path(source)/'unixnu.toml').read_bytes()
    assert b'LMIPRO ORIGINAL UFS DISPATCH v1' in app
    assert b'LMIPRO UFS ORIGINAL SERIAL LOG v1' in app
    marker='LMIPRO IOMMU ORIGINAL CALLS v1'
    assert marker.encode('ascii') in app or marker.encode('utf-16-le') in app
    title = 'LMIPRO IORT READONLY PROBE v1'
    assert title.encode('ascii') in app or title.encode('utf-16-le') in app
    return dict(boot_sha256=sha(b),boot_bytes=len(b),fd_sha256=sha(fd),fd_bytes=len(fd),
        shim_sha256=sha(shim),dtb_sha256=sha(dtb),payload_sha256=sha(payload),
        efi=pe(app),configuration=config,hardware_tested=False,contains_xnu=False,contains_os=False)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('folder');ap.add_argument('--source');args=ap.parse_args()
    print(json.dumps(verify(args.folder,args.source),indent=2))
