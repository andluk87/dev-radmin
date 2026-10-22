#!/usr/bin/env python3
"""Bounded synthetic LoginComplete/Registered experiments on original DLL code.

This extends the response research runtime with UTF-8 Windows conversion models;
packet parsing, construction and serialization remain original instructions.
"""
import argparse
import json
import struct
from pathlib import Path
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP
from response_interop import NativeResponses, field, uint32, packet, DLL_SHA256


class NativeLogin(NativeResponses):
    def __init__(self, dll):
        super().__init__(dll)
        self.api = 0x70000000
        self.u.mem_map(self.api, 0x1000)
        self.u.mem_write(0x10111108, struct.pack('<I', self.api))
        self.u.mem_write(0x10111104, struct.pack('<I', self.api + 16))
        self.unicode_calls = 0

    def _readz(self, address, unit):
        result = bytearray()
        for i in range(4096):
            part = bytes(self.u.mem_read(address + unit*i, unit))
            result.extend(part)
            if part == bytes(unit):
                return bytes(result)
        raise RuntimeError('research string too long')

    def _code(self, u, address, size, user):
        if address in (getattr(self, 'api', 0), getattr(self, 'api', 0) + 16):
            sp = u.reg_read(UC_X86_REG_ESP)
            if address == self.api:
                ret, cp, flags, src, count, dst, capacity = struct.unpack('<7I', u.mem_read(sp, 28))
                if cp != 65001 or flags != 0 or count != 0xffffffff:
                    raise RuntimeError('unsupported research UTF-8 conversion')
                result = self._readz(src, 1).decode('utf-8').encode('utf-16le')
                units, nargs = len(result)//2, 6
            else:
                ret, cp, flags, src, count, dst, capacity, default, used = struct.unpack('<9I', u.mem_read(sp, 36))
                if cp != 65001 or flags != 0 or count != 0xffffffff or default or used:
                    raise RuntimeError('unsupported research UTF-16 conversion')
                result = self._readz(src, 2).decode('utf-16le').encode('utf-8')
                units, nargs = len(result), 8
            if capacity:
                if capacity < units or not dst:
                    raise RuntimeError('invalid research string output buffer')
                u.mem_write(dst, result)
            self.unicode_calls += 1
            u.reg_write(UC_X86_REG_EAX, units)
            u.reg_write(UC_X86_REG_ESP, sp + 4*(nargs + 1))
            u.reg_write(UC_X86_REG_EIP, ret)
        else:
            super()._code(u, address, size, user)

    def factory(self, raw, mode=4):
        result = super().factory(raw, mode)
        ptr = struct.unpack('<I', self.u.mem_read(self.scratch+0x2200, 4))[0]
        if result['packet_type'] == 21:
            result['version'] = struct.unpack('<I', self.u.mem_read(ptr+0x2fc, 4))[0]
            result['field_0100025b'] = struct.unpack('<I', self.u.mem_read(ptr+0x304, 4))[0]
            result['list_1343_count'] = struct.unpack('<I', self.u.mem_read(ptr+0x3c, 4))[0]
            result['list_1340_count'] = struct.unpack('<I', self.u.mem_read(ptr+0x2f8, 4))[0]
        elif result['packet_type'] == 8:
            result['user_id'] = struct.unpack('<Q', self.u.mem_read(ptr+0x28, 8))[0]
        result['unicode_calls'] = self.unicode_calls
        return result


def login(version=75, endpoint='127.0.0.1'):
    encoded = endpoint.encode('utf-8')+b'\0'
    return packet(21, uint32(0x010001f1, version) + uint32(0x0100025b, 1)
                  +field(0x1343, field(0x0e000370, encoded))
                  +field(0x1340, field(0x0e00036c, encoded)))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dll', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args()
    native=NativeLogin(args.dll)
    modern=login()
    registered=packet(8, field(0x1233, field(0x020001e1, struct.pack('>Q',42))))
    results=[]
    for kind,raw in [('modern_login',modern),('registered',registered)]:
        result=native.factory(raw)
        print(kind,result)
        results.append({'kind':kind,'input_hex':raw.hex(),**result})
    with args.output.open('x') as f:
        json.dump({'synthetic_only':True,'dll_sha256':DLL_SHA256,
                   'scope':'Original packet factory with memory and UTF-8/UTF-16 shims; no full session state or Windows execution',
                   'cases':results},f,indent=2)
        f.write('\n')


if __name__=='__main__':main()
