#!/usr/bin/env python3
"""Offline static analysis only; never loads or executes the supplied PE files."""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

import capstone
import pefile


def offsets(data, needle):
    start = 0
    while (start := data.find(needle, start)) >= 0:
        yield start
        start += len(needle)


def analyze(path):
    data = path.read_bytes()
    pe = pefile.PE(data=data)
    base = pe.OPTIONAL_HEADER.ImageBase
    executable = [s for s in pe.sections if s.Characteristics & 0x20000000]
    noncode = [s for s in pe.sections if not s.Characteristics & 0x20000000]

    def is_code(va):
        return any(base+s.VirtualAddress <= va < base+s.VirtualAddress+s.Misc_VirtualSize for s in executable)

    def refs(va):
        needle = struct.pack('<I', va)
        return [hex(base+s.VirtualAddress+i) for s in executable for i in offsets(s.get_data(), needle)]

    result = {'file': path.name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
              'machine': hex(pe.FILE_HEADER.Machine), 'image_base': hex(base),
              'imports': {}, 'exports': {}, 'strings': [], 'rtti': []}
    for dll in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        result['imports'][dll.dll.decode(errors='replace')] = [
            {'name': i.name.decode(errors='replace') if i.name else f'ordinal:{i.ordinal}',
             'iat': hex(i.address)} for i in dll.imports]
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        result['exports'] = {s.name.decode(errors='replace'): hex(base+s.address)
                             for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
    for text in ['ServerAddress', 'ServerPassword', 'FailServers', 'ProxyServers',
                 'fail.radminte.com', 'proxy.radminte.com', 'Registration',
                 r'SOFTWARE\Famatech\RadminVPN\1.0']:
        for off in offsets(data, text.encode('utf-16le')+b'\0\0'):
            va = base+pe.get_rva_from_offset(off)
            result['strings'].append({'text': text, 'va': hex(va), 'file_offset': hex(off),
                                      'code_immediate_refs': refs(va)})
    # MSVC x86 RTTI: type descriptor -> COL (+12) -> vtable pointer (-4).
    if pe.FILE_HEADER.Machine == 0x14c:
        for match in re.finditer(rb'\.\?AVC(?:RosProtocol|RosPkt)[A-Za-z0-9_]*@RolClient@@\0', data):
            descriptor = base+pe.get_rva_from_offset(match.start()-8)
            tables = []
            for section in noncode:
                block = section.get_data()
                for pos in offsets(block, struct.pack('<I', descriptor)):
                    if pos < 12 or block[pos-12:pos-8] != b'\0'*4:
                        continue
                    col = base+section.VirtualAddress+pos-12
                    for target in noncode:
                        raw = target.get_data()
                        for vpos in offsets(raw, struct.pack('<I', col)):
                            methods = []
                            for at in range(vpos+4, min(len(raw)-3, vpos+132), 4):
                                ptr = struct.unpack_from('<I', raw, at)[0]
                                if not is_code(ptr):
                                    break
                                methods.append(hex(ptr))
                            if methods:
                                tables.append({'va': hex(base+target.VirtualAddress+vpos+4),
                                               'methods': methods})
            result['rtti'].append({'name': match.group()[:-1].decode(),
                                   'descriptor_va': hex(descriptor), 'vtables': tables})
    # A narrowly selected disassembly target gives an independently repeatable
    # check of the helper's protocol-version return value. No emulation is used.
    version = result['exports'].get('SHelper_GetNetworkProtocolVersion')
    if version:
        va = int(version, 16)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        result['protocol_version_function'] = [
            f'{ins.address:#x}: {ins.mnemonic} {ins.op_str}'.strip()
            for ins in md.disasm(pe.get_data(va-base, 6), va)]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    names = ['RvControlSvc.exe', 'RvROLClient.dll', 'shelper.dll', 'RvUESClient.dll', 'RvRvpnGui.exe']
    report = {'schema_version': 1, 'method': 'offline static PE analysis; addresses are preferred-base VAs',
              'files': [analyze(args.directory/name) for name in names]}
    args.output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(f'Saved {len(report["files"])} analyzed modules to {args.output}')


if __name__ == '__main__':
    main()
