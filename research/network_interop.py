#!/usr/bin/env python3
"""Serialize synthetic join/manage requests with original pinned RvROLClient code.

Uses request_interop's bounded allocator runtime. Does not authenticate networks,
call a server, or implement a network operation. Join proof bytes are synthetic.
"""
import argparse
import json
import struct
from pathlib import Path
from request_interop import Runtime


def serialize(r, obj):
    out = r.data(b'\0'*8)
    if not r.call(0x100167a0,obj)&255 or not r.call(0x10016770,obj,out)&255:
        raise RuntimeError('native network request serialization failed')
    ptr,size=r.get32(out),r.get32(out+4)
    if not 0<size<=4096:raise RuntimeError('unexpected native request size')
    return bytes(r.u.mem_read(ptr,size))


def generate(path):
    r=Runtime(path)
    # Base constructor consumes a two-word descriptor; its metadata does not
    # contribute to the serialized bytes. Use explicit synthetic descriptor.
    descriptor=r.data(struct.pack('<2I',75,1000))
    cases=[]
    for parameter in (0,7):
        obj=r.data(b'\0'*0x80)
        if r.call(0x10017950,obj,descriptor)!=obj:raise RuntimeError('join constructor failed')
        proof=b'synthetic-network-proof'
        proofobj=r.data(struct.pack('<2I',r.data(proof),len(proof)))
        if not r.call(0x10017a20,obj,proofobj,parameter)&255:raise RuntimeError('join proof setter failed')
        cases.append({'case':'join-synthetic-proof','command':39,'parameter':parameter,'request_hex':serialize(r,obj).hex()})
    # Network descriptor's base class is a UTF16 string buffer with a 16-byte
    # object prefix; +0x10 empty password material skips the cryptographic branch.
    for name,hidden,param3,param4,param5 in [('synthetic-network',False,0,0,0),('Тестовая сеть',True,123,4,7)]:
        obj=r.data(b'\0'*0x80)
        if r.call(0x10017950,obj,descriptor)!=obj:raise RuntimeError('join constructor failed')
        encoded_name=name.encode('utf-16le')+b'\0\0'
        network=r.data(b'\0'*0x20)
        r.u.mem_write(network,struct.pack('<4I',0x101145d4,len(encoded_name),len(encoded_name),r.data(encoded_name)))
        r.u.mem_write(network+0x18,bytes([hidden]))
        dummy_session=r.data(b'\0'*0x200)
        if not r.call(0x10017ae0,obj,dummy_session,network,param3,param4,param5)&255:
            raise RuntimeError('join descriptor setter failed')
        cases.append({'case':'join-empty-password-material','command':39,'network_name':name,'hidden':hidden,'parameter3':param3,'parameter4':param4,'parameter5':param5,'request_hex':serialize(r,obj).hex()})
    for payload in (b'synthetic-operation',struct.pack('>III',4,0x0100031f,1)):
        obj=r.data(b'\0'*0x80)
        if r.call(0x100181f0,obj,descriptor)!=obj:raise RuntimeError('manage constructor failed')
        if not r.call(0x10018280,obj,r.data(payload),len(payload))&255:raise RuntimeError('manage payload setter failed')
        cases.append({'case':'manage-opaque-operation','command':52,'operation_hex':payload.hex(),'request_hex':serialize(r,obj).hex()})
    return {'synthetic_only':True,'dll_sha256':r.sha,'scope':'Original network request serializers only. Password cryptography and server operation semantics not tested.','cases':cases}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dll',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    report=generate(a.dll)
    with a.output.open('x',encoding='utf-8') as f:
        json.dump(report,f,indent=2,ensure_ascii=False);f.write('\n')
    print('PASS native network request serializers:',len(report['cases']),'cases')


if __name__=='__main__':main()
