#!/usr/bin/env python3
"""Bounded synthetic execution of pinned RvROLClient request constructors/setters.

Only allocator and Get/SetLastError entry points are modeled. No DLL initialization or sockets.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EIP,UC_X86_REG_EAX,UC_X86_REG_ECX

class Runtime:
    def __init__(self,path):
        data=path.read_bytes()
        evidence=json.loads((Path(__file__).parent/'evidence.json').read_text())
        expected=next(f['sha256'] for f in evidence['files'] if f['file']=='RvROLClient.dll')
        if hashlib.sha256(data).hexdigest()!=expected: raise ValueError('unsupported RvROLClient DLL hash')
        self.sha=expected
        pe=pefile.PE(data=data);base=pe.OPTIONAL_HEADER.ImageBase
        self.u=Uc(UC_ARCH_X86,UC_MODE_32)
        self.u.mem_map(base,(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095)
        self.u.mem_write(base,pe.get_memory_mapped_image())
        for a,n in [(0,0x1000),(0x30000000,0x1000000),(0x40000000,0x10000),(0x50000000,0x10000)]:self.u.mem_map(a,n)
        self.next=0x30000000;self.allocations={};self.stop=0x50001000
        self.failure=None;self.trace=[];self.last_error=0
        for addr,ptr in [(0x50000000,0x10175150),(0x50000010,0x10175154),(0x50000020,0x10175158),(0x50000030,0x10111130),(0x50000040,0x1011112c)]:
            self.u.mem_write(addr,b'\xc2\x04\x00' if addr==0x50000040 else b'\xc3');self.put32(ptr,addr)
        self.u.hook_add(UC_HOOK_CODE,self.hook)
    def get32(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
    def put32(self,a,v):self.u.mem_write(a,struct.pack('<I',v))
    def alloc(self,n):
        if not 0<n<=0x100000 or self.next+n>=0x31000000:raise RuntimeError('allocation limit '+str(n))
        a=self.next;self.next+=(n+15)&~15;self.allocations[a]=n;return a
    def data(self,b):
        a=self.alloc(max(1,len(b)));self.u.mem_write(a,b);return a
    def hook(self,u,a,n,_):
        self.trace.append(a)
        if len(self.trace)>15:self.trace.pop(0)
        if a == 0x50000030:
            u.reg_write(UC_X86_REG_EAX,self.last_error)
            return
        if a == 0x50000040:
            self.last_error=self.get32(u.reg_read(UC_X86_REG_ESP)+4)
            u.reg_write(UC_X86_REG_EAX,0)
            return
        if a not in (0x50000000,0x50000010,0x50000020):return
        try:
            sp=u.reg_read(UC_X86_REG_ESP)
            if a==0x50000000:out=self.alloc(self.get32(sp+4))
            elif a==0x50000010:
                old,size=self.get32(sp+4),self.get32(sp+8)
                if old and old not in self.allocations:raise RuntimeError('unknown realloc pointer')
                out=self.alloc(size)
                if old:u.mem_write(out,bytes(u.mem_read(old,min(size,self.allocations[old]))))
            else:
                old=self.get32(sp+4)
                if old and old not in self.allocations:raise RuntimeError('unknown free pointer')
                out=0
            u.reg_write(UC_X86_REG_EAX,out)
        except Exception as e:self.failure=e;u.emu_stop()
    def call(self,a,this=0,*args):
        sp=0x40008000
        self.u.mem_write(sp,struct.pack('<'+'I'*(len(args)+1),self.stop,*args))
        self.u.reg_write(UC_X86_REG_ESP,sp);self.u.reg_write(UC_X86_REG_ECX,this)
        self.u.reg_write(UC_X86_REG_EAX,0)
        try:self.u.emu_start(a,self.stop,timeout=1000000,count=1000000)
        except Exception as e:raise RuntimeError('native failure at '+hex(self.u.reg_read(UC_X86_REG_EIP))+' trace '+str([hex(x) for x in self.trace])) from e
        if self.failure:raise self.failure
        if self.u.reg_read(UC_X86_REG_EIP)!=self.stop:raise RuntimeError('native call did not return')
        return self.u.reg_read(UC_X86_REG_EAX)
    def context(self,a):
        size=self.get32(a+4);ptr=self.get32(a+12)
        if not 0<size<=0x100000 or not ptr:raise RuntimeError('invalid native context')
        return bytes(self.u.mem_read(ptr,size))

def generate(path):
    r=Runtime(path)
    # Original static initializer only populates the descriptor for this request.
    r.call(0x10001000)
    cases=[]
    for mode in (4,5,9):
        obj=r.data(b'\0'*0x80)
        if r.call(0x10017ec0,obj,mode)!=obj:raise RuntimeError('constructor failed')
        salt=r.data(b'synthetic-machine-data')
        buffer=r.data(struct.pack('<3I',len(b'synthetic-machine-data'),len(b'synthetic-machine-data'),salt))
        # Buffer layout is size/capacity/pointer; byte-string layout is pointer/size.
        nativebuf=buffer
        stringbytes=b'synthetic-client-data'
        stringobj=r.data(struct.pack('<2I',r.data(stringbytes),len(stringbytes)))
        results=[]
        for name,fn,args in [('field_1286',0x10017f30,(nativebuf,)),('field_122f',0x10017f80,(stringobj,)),('field_1331',0x10018010,(nativebuf,)),('field_010003e0',0x10018050,(r.data(struct.pack('<I',3)),)),('field_0b000342',0x10017fe0,(1,)),('field_01000343',0x10018090,(42,0))]:
            result=r.call(fn,obj,*args)&255
            results.append({'setter':name,'accepted':bool(result)})
            if not result:raise RuntimeError('synthetic setter failed '+name)
        if mode==5:
            linked=r.data(b'\0'*8)
            first=r.data(b'\0'*16)
            second=r.data(b'\0'*16)
            r.put32(linked+4,first)
            r.put32(first+4,second)
            r.put32(second+4,linked+4)
            r.u.mem_write(first+8,struct.pack('<Q',123))
            r.u.mem_write(second+8,struct.pack('<Q',456))
            if not r.call(0x100180f0,obj,linked)&255:raise RuntimeError('mode5 repeated field failed')
            results.append({'setter':'field_0200030b_repeated','accepted':True})
        if mode==9:
            if not r.call(0x10017fb0,obj,stringobj)&255:raise RuntimeError('mode9 field_1319 failed')
            results.append({'setter':'field_1319','accepted':True})
        before=r.context(obj+0x14)
        out=r.data(b'\0'*8)
        if not r.call(0x100167a0,obj)&255:raise RuntimeError('request finalization failed')
        if not r.call(0x10016770,obj,out)&255:raise RuntimeError('request serialization failed')
        ptr,size=r.get32(out),r.get32(out+4)
        serialized=bytes(r.u.mem_read(ptr,size))
        if serialized!=before:raise RuntimeError('serialized request differs from native context body')
        cases.append({'mode':mode,'setter_results':results,'request_hex':serialized.hex(),'context_tag':hex(r.get32(obj+0x14+0x28))})
    return {'synthetic_only':True,'dll_sha256':r.sha,'scope':'Original command-20 constructor, setters and virtual serializer with modeled malloc/realloc/free and Get/SetLastError; not full Windows app','cases':cases}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dll',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    report=generate(a.dll)
    with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print('PASS native request constructor/setters/serializer:',len(report['cases']),'cases')
if __name__=='__main__':main()
