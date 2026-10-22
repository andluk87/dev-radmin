#!/usr/bin/env python3
"""Run the pinned RvROLClient TLV reader and header writer in bounded x86 emulation.

No DLL initialization or OS/API emulation is performed. Synthetic fixtures only.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EAX


def vectors(path):
    data = path.read_bytes()
    evidence = json.loads((Path(__file__).parent / 'evidence.json').read_text())
    expected = next(f['sha256'] for f in evidence['files'] if f['file'] == 'RvROLClient.dll')
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('unsupported RvROLClient DLL hash')
    pe = pefile.PE(data=data)
    base = pe.OPTIONAL_HEADER.ImageBase
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    u.mem_map(base, (pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
    u.mem_write(base, pe.get_memory_mapped_image())
    scratch, stack, stop = 0x30000000, 0x40000000, 0x50000000
    for addr in (scratch, stack, stop):
        u.mem_map(addr, 0x10000)
    cases = []
    command = struct.pack('>III', 4, 0x0100031f, 20)
    inputs = [command, struct.pack('>II', len(command), 0x1232) + command,
              struct.pack('>II', 3, 0x0a000257) + b'abc',
              b'', command[:4], command[:7], command[:-1],
              struct.pack('>II', 0, 0x1232),
              struct.pack('>II', 0xffffffff, 0x1232), command + b'trailing']
    for raw in inputs:
        u.mem_write(scratch, b'\0' * 0x1000)
        if raw:
            u.mem_write(scratch, raw)
        sp = stack + 0x8000
        outputs = [scratch + 0x800 + 4*i for i in range(3)]
        # 0x100e6090: cdecl (buffer, size, consumed*, length*, tag*).
        u.mem_write(sp, struct.pack('<6I', stop, scratch, len(raw), *outputs))
        u.reg_write(UC_X86_REG_ESP, sp)
        u.reg_write(UC_X86_REG_EIP, 0x100e6090)
        u.reg_write(UC_X86_REG_EAX, 0)
        u.emu_start(0x100e6090, stop, timeout=1000000, count=10000)
        if u.reg_read(UC_X86_REG_EIP) != stop:
            raise RuntimeError('native reader did not return within budget')
        ptr = u.reg_read(UC_X86_REG_EAX)
        result = {'input_hex': raw.hex(), 'accepted': bool(ptr)}
        if ptr:
            consumed, length, tag = [struct.unpack('<I', u.mem_read(a, 4))[0] for a in outputs]
            if ptr != scratch + 8 or consumed != length + 8 or consumed > len(raw):
                raise RuntimeError('unexpected native reader output')
            result.update(consumed=consumed, tag=tag, value_hex=bytes(u.mem_read(ptr, length)).hex())
        cases.append(result)
    encoded = []
    for tag, value in [(0x0100031f, struct.pack('>I', 20)),
                       (0x1232, command), (0x0a000257, b'synthetic')]:
        u.mem_write(scratch, b'\0' * 0x1000)
        sp = stack + 0x8000
        # 0x100e6030 writes the field header into a supplied bounded buffer.
        u.mem_write(sp, struct.pack('<7I', stop, scratch, 0, len(value), tag, 512, scratch + 0x800))
        u.reg_write(UC_X86_REG_ESP, sp)
        u.reg_write(UC_X86_REG_EAX, 0)
        u.emu_start(0x100e6030, stop, timeout=1000000, count=10000)
        if u.reg_read(UC_X86_REG_EIP) != stop or u.reg_read(UC_X86_REG_EAX) != scratch + 8:
            raise RuntimeError('native header writer failed')
        end = struct.unpack('<I', u.mem_read(scratch + 0x800, 4))[0]
        if end != len(value) + 8:
            raise RuntimeError('unexpected native header length')
        header = bytes(u.mem_read(scratch, 8))
        encoded.append({'tag': tag, 'value_hex': value.hex(),
                        'encoded_hex': (header + value).hex()})
    return {'synthetic_only': True, 'dll_sha256': expected,
            'scope': 'Original TLV reader and header writer; no Windows initialization or full control protocol',
            'reader_va': '0x100e6090', 'writer_va': '0x100e6030',
            'cases': cases, 'encoded': encoded}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dll', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = vectors(args.dll)
    with args.output.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print('PASS native TLV reader:', len(result['cases']), 'cases')


if __name__ == '__main__':
    main()
