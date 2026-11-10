"""Verify the real exec implementation and result stores, including compiler inlining."""
import struct

def audit_exec_path(data, symbols, module):
    byname={name:va for va,name in symbols.items()}
    lo,hi=module.function_range(symbols,'_load_init_program_at_path')
    def word(va):return struct.unpack_from('<I',data,module.file_offset(va))[0]
    def calls(function,target):
        start,end=module.function_range(symbols,function);result=[]
        for va in range(start,end,4):
            instruction=word(va)
            if instruction>>26!=37:continue
            delta=instruction&0x3ffffff
            if delta&(1<<25):delta-=1<<26
            if va+delta*4==byname[target]:result.append(va)
        return result
    sites=calls('_load_init_program_at_path','_execve')
    forwarded=False;target='_execve'
    if not sites:
        # Pinned original execve builds a NULL-MAC argument block and calls this
        # same implementation. Both actual wrapper and init path must call it.
        target='___mac_execve';forwarded=True
        assert len(calls('_execve',target))==1,'Original wrapper implementation changed'
        sites=calls('_load_init_program_at_path',target)
    assert len(sites)==1,'Require exactly one real init exec call'
    site=sites[0]
    # Track the literal ADRP/ADD addresses of the callee-saved diagnostic bases.
    addresses={}
    for va in range(lo,site,4):
        instruction=word(va);rd=instruction&31;rn=(instruction>>5)&31
        if instruction&0x9f000000==0x90000000:
            imm=((instruction>>5)&0x7ffff)*4+((instruction>>29)&3)
            if imm&(1<<20):imm-=1<<21
            addresses[rd]=(va&~4095)+imm*4096
        elif instruction&0xff000000==0x91000000 and rn in addresses:
            addresses[rd]=addresses[rn]+(((instruction>>10)&0xfff)<<(12 if instruction&(1<<22) else 0))
    def store_target(instruction,register):
        assert instruction&0xffc0001f==0xb9000000|register,'Expected direct 32-bit result store'
        base=(instruction>>5)&31
        assert base in addresses,'Diagnostic store base is not proven'
        return addresses[base]+((instruction>>10)&0xfff)*4
    assert store_target(word(site+4),0)==byname['_lmipro_init_error'],'execError must receive actual w0'
    stage=word(site+8)
    assert stage&0xffe00000==0x52800000 and (stage>>5)&0xffff==22
    assert store_target(word(site+12),stage&31)==byname['_lmipro_init_stage']
    return dict(actual_original_execve_call=hex(site),actual_exec_target=target,
        execve_wrapper_inlined=forwarded,actual_exec_error_store_from_w0=True,
        original_execve_result_preserved=True)
