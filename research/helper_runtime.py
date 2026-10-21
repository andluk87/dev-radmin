"""Bounded x86 research runtime for one pinned, user-supplied helper DLL.

No Windows DLL is loaded into the host process. Unicorn executes the unmodified
helper instructions with a restricted, single-thread WinAPI shim. Unsupported APIs
fail closed. The only virtual readable file is the supplied helper image.
This is not a Windows implementation, production sandbox or constant-time service.
"""

import struct, time, secrets, collections, hashlib
from pathlib import Path
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.x86_const import *


class Emulator:
    def __init__(self, path, codepage_table):
        if (
            hashlib.sha256(Path(path).read_bytes()).hexdigest()
            != "d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4"
        ):
            raise ValueError("unsupported helper DLL hash")
        if (
            hashlib.sha256(Path(codepage_table).read_bytes()).hexdigest()
            != "72ea23c939c5b26fae7aded0207b327e2f3902d7d3c168d7087f5cfc38ee76a9"
        ):
            raise ValueError("unexpected Microsoft codepage mapping hash")
        self.pe = pefile.PE(str(path))
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.cp1252 = {}
        table = False
        for line in Path(codepage_table).read_text().splitlines():
            if line.startswith("WCTABLE"):
                table = True
                continue
            if table and line.startswith("0x"):
                parts = line.split(";")[0].split()
                self.cp1252[int(parts[0], 16)] = int(parts[1], 16)
        self.u = Uc(UC_ARCH_X86, UC_MODE_32)
        u = self.u
        u.mem_map(self.base, (self.pe.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095)
        u.mem_write(self.base, self.pe.get_memory_mapped_image())
        self.stack = 0xF000000
        u.mem_map(self.stack, 0x200000)
        self.heap = 0x30000000
        self.heap_end = self.heap + 0x4000000
        u.mem_map(self.heap, 0x4000000)
        self.allocs = {}
        self.api = 0x70000000
        u.mem_map(self.api, 0x100000)
        self.next_api = self.api
        self.hooks = {}
        self.api_names = {}
        self.stop = 0x71000000
        u.mem_map(self.stop, 4096)
        u.mem_write(self.stop, b"\xf4")
        self.teb = 0x7FFDE000
        u.mem_map(self.teb, 0x4000)
        self.write32(self.teb, 0xFFFFFFFF)
        self.write32(self.teb + 4, self.stack + 0x200000)
        self.write32(self.teb + 8, self.stack)
        self.write32(self.teb + 0x18, self.teb)
        self.write32(self.teb + 0x30, self.teb + 0x1000)
        self.gdt = 0xE000000
        u.mem_map(self.gdt, 4096)

        def descriptor(base, limit, access, flags):
            return struct.pack(
                "<HHBBBB",
                limit & 65535,
                base & 65535,
                (base >> 16) & 255,
                access,
                ((limit >> 16) & 15) | (flags << 4),
                (base >> 24) & 255,
            )

        u.mem_write(self.gdt + 8, descriptor(0, 0xFFFFF, 0x9B, 0xC))
        u.mem_write(self.gdt + 16, descriptor(0, 0xFFFFF, 0x93, 0xC))
        u.mem_write(self.gdt + 24, descriptor(self.teb, 0x3FFF, 0x93, 0x4))
        u.reg_write(UC_X86_REG_GDTR, (0, self.gdt, 4095, 0))
        for reg, value in [
            (UC_X86_REG_CS, 8),
            (UC_X86_REG_DS, 16),
            (UC_X86_REG_ES, 16),
            (UC_X86_REG_SS, 16),
            (UC_X86_REG_FS, 24),
        ]:
            u.reg_write(reg, value)
        self.tls = {}
        self.next_tls = 0
        self.error = 0
        self.calls = collections.Counter()
        self.modules = {}
        self.failure = None
        self.lookups = []
        self.files = {}
        self.file_requests = []
        self.file_data = Path(path).read_bytes()
        for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in dll.imports:
                name = imp.name.decode() if imp.name else "#" + str(imp.ordinal)
                self.write32(imp.address, self.thunk(name))
        self.exports = {
            x.name.decode(): self.base + x.address
            for x in self.pe.DIRECTORY_ENTRY_EXPORT.symbols
            if x.name
        }
        u.hook_add(UC_HOOK_CODE, self.on_api, begin=self.api, end=self.api + 0xFFFFF)
        u.hook_add(UC_HOOK_MEM_INVALID, self.on_bad_memory)

    def write32(self, addr, value):
        self.u.mem_write(addr, struct.pack("<I", value & 0xFFFFFFFF))

    def read32(self, addr):
        return struct.unpack("<I", self.u.mem_read(addr, 4))[0]

    def allocate(self, size):
        size = max(16, size)
        p = self.heap
        self.heap += (size + 15) & ~15
        if self.heap > self.heap_end:
            raise RuntimeError("heap budget exceeded")
        self.allocs[p] = size
        return p

    def data(self, b):
        p = self.allocate(len(b))
        self.u.mem_write(p, b)
        return p

    def cstring(self, p, wide=False):
        if not p:
            return ""
        out = bytearray()
        step = 2 if wide else 1
        for i in range(65536):
            b = bytes(self.u.mem_read(p + i * step, step))
            if b == b"\0" * step:
                return out.decode("utf-16le" if wide else "ascii")
            out += b
        raise RuntimeError("unterminated string")

    def thunk(self, name):
        if name not in self.api_names:
            p = self.next_api
            self.next_api += 16
            self.api_names[name] = p
            self.hooks[p] = name
            self.u.mem_write(p, b"\xc3")
        return self.api_names[name]

    def on_bad_memory(self, u, access, addr, size, value, data):
        self.failure = RuntimeError(
            f"unmapped access {access} at {addr:#x} from {u.reg_read(UC_X86_REG_EIP):#x}"
        )
        return False

    def on_api(self, u, addr, size, data):
        try:
            name = self.hooks[addr]
            self.calls[name] += 1
            sp = u.reg_read(UC_X86_REG_ESP)

            def a(n):
                return self.read32(sp + 4 + 4 * n)

            argc, result = self.dispatch(name, a)
            if isinstance(result, tuple):
                u.reg_write(UC_X86_REG_EDX, result[1])
                result = result[0]
            u.reg_write(UC_X86_REG_EAX, result & 0xFFFFFFFF)
            u.reg_write(UC_X86_REG_EIP, self.read32(sp))
            u.reg_write(UC_X86_REG_ESP, sp + 4 + argc * 4)
        except Exception as e:
            self.failure = e
            u.emu_stop()

    def dispatch(self, name, a):
        noops = {
            "InitializeCriticalSection": 1,
            "EnterCriticalSection": 1,
            "LeaveCriticalSection": 1,
            "DeleteCriticalSection": 1,
            "Sleep": 1,
            "OutputDebugStringW": 1,
        }
        if name in noops:
            return noops[name], 0
        if name == "InitializeCriticalSectionAndSpinCount":
            return 2, 1
        if name == "InterlockedCompareExchange":
            old = self.read32(a(0))
            if old == a(2):
                self.write32(a(0), a(1))
            return 3, old
        if name == "InterlockedExchange":
            old = self.read32(a(0))
            self.write32(a(0), a(1))
            return 2, old
        if name == "GetProcessHeap":
            return 0, 1
        if name == "HeapAlloc":
            return 3, self.allocate(a(2))
        if name == "HeapFree":
            if a(2):
                self.allocs.pop(a(2))
            return 3, 1
        if name == "HeapSize":
            return 3, self.allocs[a(2)]
        if name == "HeapReAlloc":
            old = a(2)
            size = a(3)
            p = self.allocate(size)
            self.u.mem_write(
                p, bytes(self.u.mem_read(old, min(size, self.allocs[old])))
            )
            self.allocs.pop(old)
            return 4, p
        if name == "TlsAlloc":
            n = self.next_tls
            self.next_tls += 1
            self.tls[n] = 0
            return 0, n
        if name == "TlsGetValue":
            return 1, self.tls[a(0)]
        if name == "TlsSetValue":
            self.tls[a(0)] = a(1)
            return 2, 1
        if name == "TlsFree":
            self.tls.pop(a(0))
            return 1, 1
        if name == "GetVersion":
            return 0, 0x4A65000A
        if name == "GetCurrentProcessId":
            return 0, 100
        if name == "GetCurrentThreadId":
            return 0, 101
        if name == "GetCurrentProcess":
            return 0, 0xFFFFFFFF
        if name == "GetTickCount":
            return 0, int(time.monotonic() * 1000) & 0xFFFFFFFF
        if name == "QueryPerformanceCounter":
            self.u.mem_write(a(0), struct.pack("<Q", time.perf_counter_ns() // 100))
            return 1, 1
        if name == "QueryPerformanceFrequency":
            self.u.mem_write(a(0), struct.pack("<Q", 10000000))
            return 1, 1
        if name == "GetSystemTimeAsFileTime":
            self.u.mem_write(
                a(0),
                struct.pack("<Q", int(time.time() * 10000000) + 116444736000000000),
            )
            return 1, 0
        if name == "GetLastError":
            return 0, self.error
        if name == "SetLastError":
            self.error = a(0)
            return 1, 0
        if name == "IsDebuggerPresent":
            return 0, 0
        if name == "IsProcessorFeaturePresent":
            return 1, 0
        if name == "GetStartupInfoW":
            self.u.mem_write(a(0), struct.pack("<I", 68) + b"\0" * 64)
            return 1, 0
        if name in [
            "GetModuleHandleA",
            "GetModuleHandleW",
            "LoadLibraryA",
            "LoadLibraryW",
        ]:
            s = self.cstring(a(0), name.endswith("W")).lower()
            if not s or s.endswith("shelper.dll"):
                return 1, self.base
            if s not in (
                "kernel32.dll",
                "advapi32.dll",
                "user32.dll",
                "crypt32.dll",
                "netapi32.dll",
                "ntdll.dll",
            ):
                self.error = 126
                return 1, 0
            if s not in self.modules:
                self.modules[s] = 0x72000000 + len(self.modules) * 0x10000
            return 1, self.modules[s]
        if name == "GetProcAddress":
            s = self.cstring(a(1))
            self.lookups.append(s)
            supported = [
                "FlsAlloc",
                "FlsFree",
                "FlsGetValue",
                "FlsSetValue",
                "GetTickCount64",
                "SystemFunction036",
                "CryptAcquireContextA",
                "CryptAcquireContextW",
                "CryptGenRandom",
                "CryptReleaseContext",
                "GetSystemTimeAsFileTime",
                "QueryPerformanceCounter",
                "QueryPerformanceFrequency",
                "GetCurrentThreadId",
                "GetCurrentProcessId",
                "GetTickCount",
                "InitializeCriticalSectionAndSpinCount",
                "EncodePointer",
                "DecodePointer",
            ]
            return 2, self.thunk(s) if s in supported else 0
        if name == "GetTickCount64":
            v = int(time.monotonic() * 1000)
            return 0, (v & 0xFFFFFFFF, v >> 32)
        if name in ["EncodePointer", "DecodePointer"]:
            return 1, a(0)
        if name == "FlsAlloc":
            _, value = self.dispatch("TlsAlloc", a)
            return 1, value
        if name.startswith("Fls"):
            return self.dispatch(name.replace("Fls", "Tls"), a)
        if name == "FreeLibrary":
            return 1, 1
        if name == "GetACP":
            return 0, 1252
        if name == "GetDesktopWindow":
            return 0, 0
        if name == "GetProcessWindowStation":
            return 0, 0
        if name == "GetCPInfo":
            cp = a(0)
            if cp not in (0, 1252, 437, 65001):
                raise RuntimeError("unsupported codepage")
            self.u.mem_write(
                a(1), struct.pack("<I", 4 if cp == 65001 else 1) + b"?\0" + b"\0" * 14
            )
            return 2, 1
        if name == "GetStringTypeW":
            import unicodedata

            if a(0) != 1:
                raise RuntimeError("unsupported character classification type")
            text = bytes(self.u.mem_read(a(1), a(2) * 2)).decode("utf-16le")
            flags = []
            for c in text:
                category = unicodedata.category(c)
                v = 0
                if c.isupper():
                    v |= 1
                if c.islower():
                    v |= 2
                if category == "Nd":
                    v |= 4
                if c.isspace():
                    v |= 8
                if category.startswith("P") or category.startswith("S"):
                    v |= 16
                if category == "Cc":
                    v |= 32
                if c in "\t " or category == "Zs":
                    v |= 64
                if c in "0123456789abcdefABCDEF":
                    v |= 128
                if c.isalpha():
                    v |= 256
                flags.append(v)
            self.u.mem_write(a(3), struct.pack("<" + "H" * len(flags), *flags))
            return 4, 1
        if name == "LCMapStringW":
            flags = a(1)
            count = a(3)
            if flags not in (0x100, 0x200):
                raise RuntimeError(f"unsupported locale mapping flags {flags:#x}")
            text = (
                self.cstring(a(2), True) + "\0"
                if count == 0xFFFFFFFF
                else bytes(self.u.mem_read(a(2), count * 2)).decode("utf-16le")
            )
            out = "".join(
                (
                    (c.lower() if flags == 0x100 else c.upper())
                    if len(c.lower() if flags == 0x100 else c.upper()) == 1
                    else c
                )
                for c in text
            ).encode("utf-16le")
            length = len(out) // 2
            if a(5) == 0:
                return 6, length
            if a(5) < length:
                self.error = 122
                return 6, 0
            self.u.mem_write(a(4), out)
            return 6, length
        if name == "GetOEMCP":
            return 0, 437
        if name == "IsValidCodePage":
            return 1, int(a(0) in (1252, 437, 65001))
        if name == "GetCommandLineA":
            return 0, self.data(b"research.exe\0")
        if name in ("GetModuleFileNameA", "GetModuleFileNameW"):
            wide = name.endswith("W")
            s = (
                "C:\\research\\shelper.dll"
                if a(0) == self.base
                else "C:\\research\\harness.exe"
            )
            cap = a(2)
            text = s[:cap] if cap <= len(s) else s + "\0"
            self.u.mem_write(a(1), text.encode("utf-16le" if wide else "ascii"))
            return 3, min(len(s), cap)
        if name == "GetEnvironmentStringsW":
            return 0, self.data(b"\0" * 4)
        if name == "CreateFileW":
            path = self.cstring(a(0), True)
            self.file_requests.append(path)
            if (
                path.lower() != "c:\\research\\shelper.dll"
                or a(1) & 0x40000000
                or a(4) != 3
            ):
                self.error = 2
                return 7, 0xFFFFFFFF
            handle = 0x5200 + len(self.files)
            self.files[handle] = [self.file_data, 0]
            return 7, handle
        if name == "GetFileSize":
            if a(1):
                self.write32(a(1), 0)
            return 2, len(self.files[a(0)][0])
        if name == "ReadFile":
            if a(4):
                raise RuntimeError("overlapped file reads unsupported")
            data, pos = self.files[a(0)]
            b = data[pos : pos + a(2)]
            self.u.mem_write(a(1), b)
            self.write32(a(3), len(b))
            self.files[a(0)][1] += len(b)
            return 5, 1
        if name == "SetFilePointerEx":
            data, pos = self.files[a(0)]
            distance = (a(2) << 32) | a(1)
            if distance & (1 << 63):
                distance -= 1 << 64
            target = {0: 0, 1: pos, 2: len(data)}[a(4)] + distance
            if target < 0:
                raise RuntimeError("negative file seek")
            self.files[a(0)][1] = target
            if a(3):
                self.u.mem_write(a(3), struct.pack("<Q", target))
            return 5, 1
        if name == "CloseHandle":
            if a(0) not in self.files:
                raise RuntimeError("unknown virtual handle")
            self.files.pop(a(0))
            return 1, 1
        if name == "WideCharToMultiByte":
            cp = a(0)
            count = a(3)
            text = (
                self.cstring(a(2), True) + "\0"
                if count == 0xFFFFFFFF
                else bytes(self.u.mem_read(a(2), count * 2)).decode("utf-16le")
            )
            enc = {
                0: "cp1252",
                3: "cp1252",
                1: "cp437",
                1252: "cp1252",
                437: "cp437",
                65001: "utf-8",
            }[cp]
            if enc == "cp1252":
                b = bytes(self.cp1252.get(ord(c), 63) for c in text)
            else:
                b = text.encode(enc)
            if a(7):
                self.write32(
                    a(7),
                    (
                        int(any(ord(c) not in self.cp1252 for c in text))
                        if enc == "cp1252"
                        else 0
                    ),
                )
            if a(5) == 0:
                return 8, len(b)
            if a(5) < len(b):
                self.error = 122
                return 8, 0
            self.u.mem_write(a(4), b)
            return 8, len(b)
        if name == "MultiByteToWideChar":
            cp = a(0)
            count = a(3)
            enc = {
                0: "cp1252",
                3: "cp1252",
                1: "cp437",
                1252: "cp1252",
                437: "cp437",
                65001: "utf-8",
            }[cp]
            b = (
                self.cstring(a(2)).encode("ascii") + b"\0"
                if count == 0xFFFFFFFF
                else bytes(self.u.mem_read(a(2), count))
            )
            if enc == "cp1252":
                text = "".join(
                    (
                        chr(v)
                        if v in (0x81, 0x8D, 0x8F, 0x90, 0x9D)
                        else bytes([v]).decode(enc)
                    )
                    for v in b
                )
            else:
                text = b.decode(enc)
            out = text.encode("utf-16le")
            length = len(out) // 2
            if a(5) == 0:
                return 6, length
            if a(5) < length:
                self.error = 122
                return 6, 0
            self.u.mem_write(a(4), out)
            return 6, length
        if name == "FreeEnvironmentStringsW":
            return 1, 1
        if name == "SetUnhandledExceptionFilter":
            return 1, 0
        if name == "GetStdHandle":
            return 1, 0xFFFFFFFF
        if name == "GetFileType":
            return 1, 0
        if name == "GlobalMemoryStatus":
            self.u.mem_write(
                a(0),
                struct.pack(
                    "<8I", 32, 50, 1 << 30, 1 << 29, 1 << 30, 1 << 29, 1 << 30, 1 << 29
                ),
            )
            return 1, 0
        if name == "GetVersionExA":
            size = self.read32(a(0))
            self.u.mem_write(
                a(0), struct.pack("<5I", size, 10, 0, 19045, 2) + b"\0" * (size - 20)
            )
            return 1, 1
        if name in ("CryptAcquireContextA", "CryptAcquireContextW"):
            self.write32(a(0), 0x5151)
            return 5, 1
        if name == "CryptReleaseContext":
            return 2, 1
        if name == "CryptGenRandom":
            self.u.mem_write(a(2), secrets.token_bytes(a(1)))
            return 3, 1
        if name == "SystemFunction036":
            self.u.mem_write(a(0), secrets.token_bytes(a(1)))
            return 2, 1
        raise RuntimeError("unsupported WinAPI " + name)

    def call(self, fn, *args):
        self.failure = None
        sp = self.stack + 0x1F0000
        values = [self.stop] + list(args)
        self.u.mem_write(sp, struct.pack("<" + "I" * len(values), *values))
        self.u.reg_write(UC_X86_REG_ESP, sp)
        self.u.reg_write(UC_X86_REG_EFLAGS, 0x202)
        start = self.exports.get(fn, fn) if isinstance(fn, str) else fn
        try:
            self.u.emu_start(start, self.stop, timeout=10_000_000, count=500_000_000)
        except Exception as e:
            if not self.failure:
                self.failure = e
        if self.failure:
            raise self.failure
        if self.u.reg_read(UC_X86_REG_EIP) != self.stop:
            raise RuntimeError(
                f"budget exhausted at {self.u.reg_read(UC_X86_REG_EIP):#x}"
            )
        return self.u.reg_read(UC_X86_REG_EAX)
