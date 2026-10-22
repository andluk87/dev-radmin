#!/usr/bin/env python3
"""Validate synthetic ROS responses with pinned original RvROLClient code.

The selected decoders run without protocol stubs or Windows API shims. The full
packet factory and serializer additionally model memory allocation in local
bounded memory. This does not initialize the DLL or execute a Windows client.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_ESP, UC_X86_REG_EIP

DLL_SHA256 = '6ba7dfecd38183d4bff0fc53f1c8c05d25e636077fe753b1220912aa58938177'


def field(tag, value):
    return struct.pack('>II', len(value), tag) + value


def uint32(tag, value):
    return field(tag, struct.pack('>I', value))


def packet(kind, body):
    return uint32(0x01000320, kind) + body


class NativeResponses:
    """One bounded image with scratch-only decoders and a memory-only factory."""
    DECODERS = {'error': 0x1008c490, 'login_complete': 0x1008ca50,
                'is_alive': 0x1008c6c0}

    def __init__(self, dll):
        data = Path(dll).read_bytes()
        if hashlib.sha256(data).hexdigest() != DLL_SHA256:
            raise ValueError('unsupported RvROLClient DLL hash')
        pe = pefile.PE(data=data)
        self.u = Uc(UC_ARCH_X86, UC_MODE_32)
        base = pe.OPTIONAL_HEADER.ImageBase
        self.u.mem_map(base, (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
        self.u.mem_write(base, pe.get_memory_mapped_image())
        self.scratch, self.stack, self.stop = 0x30000000, 0x40008000, 0x50000000
        # Zero-based FS anchor supplies SEH storage, not an OS implementation.
        self.u.mem_map(0, 0x10000)
        self.u.mem_map(self.scratch, 0x100000)
        self.u.mem_map(0x40000000, 0x10000)
        self.u.mem_map(self.stop, 0x1000)
        self.allocated = self.scratch + 0x10000
        self.model_allocation = False
        self.allocation_calls = 0
        self.allocations = {}
        self.u.hook_add(UC_HOOK_CODE, self._code)

    def _code(self, u, address, size, user):
        if self.model_allocation and address in (0x100f1470, 0x100f587b, 0x100f58a1):
            sp = u.reg_read(UC_X86_REG_ESP)
            ret, length = struct.unpack('<II', u.mem_read(sp, 8))
            previous = 0
            if address == 0x100f58a1:
                previous, length = struct.unpack('<II', u.mem_read(sp + 4, 8))
            if not 0 < length <= 65536:
                raise RuntimeError('allocation outside research budget')
            ptr = (self.allocated + 15) & ~15
            self.allocated = ptr + length
            if self.allocated > self.scratch + 0x100000:
                raise RuntimeError('research heap exhausted')
            u.mem_write(ptr, bytes(length))
            if previous:
                if previous not in self.allocations:
                    raise RuntimeError("unknown research realloc pointer")
                count = min(length, self.allocations[previous])
                u.mem_write(ptr, bytes(u.mem_read(previous, count)))
            self.allocations[ptr] = length
            self.allocation_calls += 1
            u.reg_write(UC_X86_REG_EAX, ptr)
            u.reg_write(UC_X86_REG_ESP, sp + 4)
            u.reg_write(UC_X86_REG_EIP, ret)

        elif self.model_allocation and address == 0x100f5886:
            sp = u.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack('<I', u.mem_read(sp, 4))[0]
            u.reg_write(UC_X86_REG_ESP, sp + 4)
            u.reg_write(UC_X86_REG_EIP, ret)

    def alive_reply(self, nonce):
        self._reset(b'\0')
        self.model_allocation = True
        obj, context = self.scratch + 0x3000, self.scratch + 0x4000
        self.u.mem_write(obj + 0x20, struct.pack('<Q', nonce))
        if self._call(0x10088e90, obj, context) & 255 != 1:
            raise RuntimeError('native IsAlive reply serializer failed')
        size = struct.unpack('<I', self.u.mem_read(context + 4, 4))[0]
        ptr = struct.unpack('<I', self.u.mem_read(context + 0xc, 4))[0]
        if not ptr or not 0 < size <= 4096:
            raise RuntimeError('invalid native reply output')
        return bytes(self.u.mem_read(ptr, size))

    def _reset(self, raw):
        if not 0 < len(raw) <= 4096:
            raise ValueError('synthetic response outside research budget')
        self.u.mem_write(self.scratch, bytes(0x8000))
        self.u.mem_write(self.scratch, raw)
        self.allocated = self.scratch + 0x10000
        self.allocation_calls = 0

    def _call(self, address, this, *args):
        self.u.mem_write(self.stack, struct.pack('<' + 'I' * (1 + len(args)), self.stop, *args))
        self.u.reg_write(UC_X86_REG_ESP, self.stack)
        self.u.reg_write(UC_X86_REG_ECX, this)
        self.u.reg_write(UC_X86_REG_EAX, 0)
        self.u.emu_start(address, self.stop, timeout=1000000, count=200000)
        if self.u.reg_read(UC_X86_REG_EIP) != self.stop:
            raise RuntimeError('original code exceeded execution budget')
        return self.u.reg_read(UC_X86_REG_EAX)

    def _view(self, raw):
        view = self.scratch + 0x2000
        if self._call(0x100a7760, view, 0x124f, self.scratch, len(raw)) != 1:
            raise RuntimeError('native parser view initialization failed')
        return view

    def decode(self, kind, raw, mode=4):
        """Run the selected decoder; selection itself is not asserted here."""
        self._reset(raw)
        self.model_allocation = False
        view = self._view(raw)
        obj = self.scratch + 0x3000
        self.u.mem_write(obj + 4, struct.pack('<I', mode))
        accepted = bool(self._call(self.DECODERS[kind], obj, view) & 255)
        result = {'accepted': accepted}
        if accepted:
            if kind == 'error':
                result['code'] = struct.unpack('<I', self.u.mem_read(obj + 0x28, 4))[0]
            elif kind == 'is_alive':
                result['nonce'] = struct.unpack('<Q', self.u.mem_read(obj + 0x20, 8))[0]
            else:
                result['version'] = struct.unpack('<I', self.u.mem_read(obj + 0x2f4, 4))[0]
                result['field_0100025b'] = struct.unpack('<I', self.u.mem_read(obj + 0x2fc, 4))[0]
        return result

    def factory(self, raw, mode=4):
        """Run actual type dispatch and decoder with local allocator shims."""
        self._reset(raw)
        self.model_allocation = True
        view = self._view(raw)
        pair, output, extra = (self.scratch + a for a in (0x2100, 0x2200, 0x2300))
        ok = self._call(0x1008a790, 0, mode, pair, view, output, extra)
        ptr = struct.unpack('<I', self.u.mem_read(output, 4))[0]
        if not ok or not ptr:
            raise RuntimeError('native packet factory failed')
        actual_type = struct.unpack('<I', self.u.mem_read(ptr + 0x18, 4))[0]
        result = {'accepted': True, 'packet_type': actual_type,
                  'allocation_calls': self.allocation_calls}
        if actual_type == 16:
            result['code'] = struct.unpack('<I', self.u.mem_read(ptr + 0x30, 4))[0]
        elif actual_type == 18:
            result['nonce'] = struct.unpack('<Q', self.u.mem_read(ptr + 0x28, 8))[0]
        return result


def vectors(native):
    cases = []
    code = uint32(0x010001d2, 1)
    error = packet(16, field(0x123b, code))
    error7 = packet(16, field(0x123b, uint32(0x010001d2, 7)))
    alive = packet(18, field(0x1267, field(0x02000232, struct.pack('>Q', 0x1122334455667788))))
    legacy = packet(21, uint32(0x010001f1, 16) + uint32(0x0100025b, 1))
    modern = packet(21, uint32(0x010001f1, 75) + uint32(0x0100025b, 1))
    samples = [
        ('error', error, True), ('error', error7, True),
        ('error', packet(16, field(0x123b, uint32(0x010001d1, 1))), False),
        ('error', packet(16, field(0x123b, field(0x010001d2, b'\x01'))), False),
        ('error', packet(16, code), False),
        ('is_alive', alive, True),
        ('is_alive', packet(18, field(0x1267, uint32(0x02000232, 1))), False),
        ('login_complete', legacy, True), ('login_complete', modern, False),
    ]
    for kind, raw, expected in samples:
        result = native.decode(kind, raw)
        if result['accepted'] != expected:
            raise RuntimeError('unexpected original decoder result: '+kind+' '+str(result))
        cases.append({'kind': kind, 'input_hex': raw.hex(), **result})
    factory = []
    for raw in (error, error7, alive):
        factory.append({'input_hex': raw.hex(), **native.factory(raw)})
    reply = native.alive_reply(0x1122334455667788)
    return {'synthetic_only': True, 'dll_sha256': DLL_SHA256,
            'scope': 'Selected original decoders plus actual Error/IsAlive packet factory; memory allocation shims for factory and serializer; no full client state or Windows execution',
            'mode': 4, 'factory_va': '0x1008a790',
            'cases': cases, 'factory': factory,
            'is_alive_reply': {'nonce': 0x1122334455667788, 'encoded_hex': reply.hex()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dll', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = vectors(NativeResponses(args.dll))
    with args.output.open('x') as target:
        json.dump(report, target, indent=2)
        target.write('\n')
    print('PASS native responses:', len(report['cases']), 'decoders;', len(report['factory']), 'factory cases')


if __name__ == '__main__':
    main()
