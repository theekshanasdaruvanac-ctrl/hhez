"""Minimal PE32+ reader: sections, .text access, RVA/VA mapping, exports.

Read-only, file-backed, no dependencies beyond stdlib. The pipeline never
maps the image — every address is resolved through section headers, so a
malformed or hostile PE can at worst yield garbage RVAs that later gates
reject. Bounds are checked on every access.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path


class PEError(Exception):
    pass


IMAGE_FILE_MACHINE_AMD64 = 0x8664

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3  # .pdata on PE32+

MEM_COMMIT_R = 0x40000000  # IMAGE_SCN_MEM_READ
MEM_COMMIT_W = 0x80000000  # IMAGE_SCN_MEM_WRITE
MEM_COMMIT_X = 0x20000000  # IMAGE_SCN_MEM_EXECUTE
CNT_CODE = 0x00000020


@dataclass
class Section:
    name: str
    rva: int
    vsize: int          # virtual size
    raw_ptr: int
    raw_size: int       # size of raw data
    chars: int

    @property
    def executable(self) -> bool:
        return bool(self.chars & (MEM_COMMIT_X | CNT_CODE))

    @property
    def readable(self) -> bool:
        return bool(self.chars & MEM_COMMIT_R)

    def span(self) -> int:
        # A section with no raw content (runtime-mapped) still occupies VA.
        return max(self.vsize, 0)

    def contains(self, rva: int) -> bool:
        return self.rva <= rva < self.rva + self.vsize


@dataclass
class Export:
    name: str
    ordinal: int
    rva: int
    forwarded: bool = False


@dataclass
class Image:
    path: Path
    data: bytes
    machine: int
    preferred_base: int
    entry: int
    size_of_image: int
    sections: list[Section] = field(default_factory=list)
    data_dirs: dict[int, tuple[int, int]] = field(default_factory=dict)
    _by_rva: list[Section] = field(default_factory=list, repr=False)

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, path: str | Path) -> "Image":
        path = Path(path)
        data = path.read_bytes()
        if len(data) < 0x40:
            raise PEError(f"{path}: too small for a PE header")
        if data[:2] != b"MZ":
            raise PEError(f"{path}: no MZ signature")
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\0\0":
            raise PEError(f"{path}: no PE signature")
        coff = pe_off + 4
        machine, nsec, _, _, _, size_opt, chars = struct.unpack_from(
            "<HHIIIHH", data, coff)
        opt = coff + 20
        if opt + size_opt > len(data):
            raise PEError(f"{path}: truncated optional header")
        magic = struct.unpack_from("<H", data, opt)[0]
        if magic != 0x20B:
            raise PEError(f"{path}: not PE32+ (magic 0x{magic:03X})")
        entry = struct.unpack_from("<I", data, opt + 16)[0]
        size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        preferred_base = struct.unpack_from("<Q", data, opt + 24)[0]
        dd_off = opt + 112
        n_dd = struct.unpack_from("<I", data, opt + 108)[0]
        dirs: dict[int, tuple[int, int]] = {}
        for i in range(min(n_dd, 16)):
            rva, size = struct.unpack_from("<II", data, dd_off + i * 8)
            if size:
                dirs[i] = (rva, size)

        sec_off = opt + size_opt
        sections: list[Section] = []
        for i in range(nsec):
            o = sec_off + i * 40
            if o + 40 > len(data):
                raise PEError(f"{path}: truncated section table")
            raw_name = data[o:o + 8].rstrip(b"\0")
            vsize, srva, vraw, ptr, psize = struct.unpack_from("<IIIII", data, o + 8)
            cflags = struct.unpack_from("<I", data, o + 36)[0]
            sections.append(Section(
                name=raw_name.decode("latin-1", "replace"), rva=srva, vsize=vsize,
                raw_ptr=ptr, raw_size=psize, chars=cflags))

        # FiveM strips SizeOfRawData to 0 in every DLL it ships. The bytes are
        # all present; each section's raw extent runs from its PointerToRawData
        # to the next section's pointer (file size for the last one). Infer it
        # whenever the header lies.
        by_ptr = sorted((s for s in sections if s.raw_ptr),
                        key=lambda s: s.raw_ptr)
        for idx, s in enumerate(by_ptr):
            end = by_ptr[idx + 1].raw_ptr if idx + 1 < len(by_ptr) else len(data)
            inferred = max(0, end - s.raw_ptr)
            if s.raw_size == 0:
                s.raw_size = inferred
            else:
                s.raw_size = max(s.raw_size, min(inferred, s.vsize or inferred))
        img = cls(path=path, data=data, machine=machine,
                  preferred_base=preferred_base, entry=entry,
                  size_of_image=size_of_image, sections=sections, data_dirs=dirs)
        img._by_rva = sorted(sections, key=lambda s: s.rva)
        return img

    # ----------------------------------------------------------------- access
    def size(self) -> int:
        """Virtual image size (RVAs live in [0, size()))."""
        return self.size_of_image or max(
            (s.rva + s.span() for s in self.sections), default=0)

    def section_by_name(self, name: str) -> Section | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def exec_sections(self) -> list[Section]:
        return [s for s in self.sections if s.executable and s.readable]

    def text(self) -> Section:
        s = self.section_by_name(".text")
        if s is None:
            ex = self.exec_sections()
            if not ex:
                raise PEError(f"{self.path}: no executable section")
            s = max(ex, key=lambda x: x.vsize)
        return s

    def section_of(self, rva: int) -> Section | None:
        lo, hi = 0, len(self._by_rva) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            s = self._by_rva[mid]
            if rva < s.rva:
                hi = mid - 1
            elif rva >= s.rva + s.span():
                lo = mid + 1
            else:
                return s
        return None

    def in_range(self, rva: int, n: int = 1) -> bool:
        s = self.section_of(rva)
        return s is not None and s.raw_size >= (rva - s.rva) + n > 0

    def read(self, rva: int, n: int) -> bytes | None:
        """Raw file bytes backing [rva, rva+n), or None if not file-backed."""
        s = self.section_of(rva)
        if s is None:
            return None
        off = s.raw_ptr + (rva - s.rva)
        if s.raw_size == 0 or (rva - s.rva) + n > s.raw_size:
            return None
        chunk = self.data[off:off + n]
        return chunk if len(chunk) == n else None

    def rva_of_offset(self, file_off: int) -> int | None:
        for s in self._by_rva:
            if s.raw_size and s.raw_ptr <= file_off < s.raw_ptr + s.raw_size:
                return s.rva + (file_off - s.raw_ptr)
        return None

    def code_hash(self) -> int:
        """64-bit FNV-1a over all file-backed executable-section bytes.

        Cheap build identity: any code-byte change flips it.
        """
        h = 0xCBF29CE484222325
        for s in sorted(self.exec_sections(), key=lambda x: x.rva):
            blob = self.read(s.rva, min(s.raw_size, s.vsize or s.raw_size)) or b""
            for b in blob:
                h ^= b
                h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
        return h

    # ---------------------------------------------------------------- exports
    def exports(self) -> list[Export]:
        d = self.data_dirs.get(IMAGE_DIRECTORY_ENTRY_EXPORT)
        if not d:
            return []
        rva, _ = d
        hdr = self.read(rva, 40)
        if hdr is None:
            return []
        # IMAGE_EXPORT_DIRECTORY (offsets): Characteristics 0, TimeDateStamp 4,
        # Maj 8 Min 10, Name 12, OrdinalBase 16, NumFunctions 20, NumNames 24,
        # AddressOfFunctions 28, AddressOfNames 32, AddressOfNameOrdinals 36.
        (flags, tstamp, _mj, _mn, name_rva, ordinal_base, nfuncs, nnames,
         addr_of_funcs, addr_of_names,
         addr_of_ordinals) = struct.unpack_from("<IIHHIIIIIII", hdr, 0)
        if not addr_of_names:
            return []
        # AddressOf* fields are RVAs, not directory-relative offsets.
        names = self.read(addr_of_names, nnames * 4)
        funcs = self.read(addr_of_funcs, nfuncs * 4)
        ords = self.read(addr_of_ordinals, nnames * 2) if nnames else b""
        if not names or not funcs:
            return []
        out: list[Export] = []
        exp_end = rva + (self.data_dirs.get(IMAGE_DIRECTORY_ENTRY_EXPORT, (0, 0))[1] or 0)
        for i in range(nnames):
            nrva = struct.unpack_from("<I", names, i * 4)[0]
            # NameOrdinals[i] selects the function slot — names and functions
            # are not parallel arrays.
            fn_slot = struct.unpack_from("<H", ords, i * 2)[0] if ords else i
            if fn_slot >= nfuncs:
                continue
            fn_rva = struct.unpack_from("<I", funcs, fn_slot * 4)[0]
            # forwarded: function RVA lands inside the export directory itself
            fwd = bool(exp_end) and rva <= fn_rva < exp_end
            # name string may span past a section-aligned read; walk bytes
            nm = bytearray()
            for k in range(256):
                b = self.read(nrva + k, 1)
                if b is None or b == b"\0":
                    break
                nm += b
            out.append(Export(nm.decode("latin-1", "replace"),
                              ordinal_base + struct.unpack_from("<H", ords, i * 2)[0] if ords else i,
                              fn_rva, fwd))
        return out
