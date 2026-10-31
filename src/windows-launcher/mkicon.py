#!/usr/bin/env python3
"""Build mautg.ico (paw logo) and rsrc_windows_amd64.syso (icon + manifest resources
for the Go linker). Usage: python3 mkicon.py"""
import struct, io, os
from PIL import Image, ImageDraw

BG, FG = (74, 59, 52, 255), (243, 233, 220, 255)   # paw brown / cream

SRC = '/tmp/work/ic3/mautg-icon-1024.png'
_base = Image.open(SRC).convert('RGBA')
_base = _base.crop(_base.getbbox())

def logo(size):
    """mautg icon (paw + MAUTG text on the brown tile) from icon/mautg-icon-1024.png."""
    return _base.resize((size, size), Image.LANCZOS)

SIZES = [16, 24, 32, 48, 64, 256]

def dib(im):
    w, h = im.size
    px = im.load()
    rows = bytearray()
    for y in range(h - 1, -1, -1):
        for x in range(w):
            r, g, b, a = px[x, y]
            rows += bytes((b, g, r, a))
    mask_row = ((w + 31) // 32) * 4
    hdr = struct.pack('<IiiHHIIiiII', 40, w, h * 2, 1, 32, 0, len(rows), 0, 0, 0, 0)
    return hdr + bytes(rows) + bytes(mask_row * h)

def png(im):
    b = io.BytesIO(); im.save(b, 'PNG'); return b.getvalue()

images = []
for s in SIZES:
    im = logo(s)
    images.append((s, png(im) if s >= 256 else dib(im)))

# ---- .ico ----
ico = struct.pack('<HHH', 0, 1, len(images))
off = 6 + 16 * len(images)
for s, data in images:
    ico += struct.pack('<BBBBHHII', s % 256, s % 256, 0, 0, 1, 32, len(data), off)
    off += len(data)
ico += b''.join(d for _, d in images)
for d in ('.', '../osx-installer/res', '../osx-launcher/res', '../windows-installer'):
    os.makedirs(d, exist_ok=True)
for d in ('.', '../osx-installer/res', '../osx-launcher/res'):
    open(os.path.join(d, 'mautg.ico'), 'wb').write(ico)
    logo(256).save(os.path.join(d, 'mautg-logo.png'))
import shutil; shutil.copy('/tmp/work/ic3/mautg.icns','../osx-launcher/res/mautg.icns')

# ---- resources: RT_ICON (3) x n, RT_GROUP_ICON (14), RT_MANIFEST (24) ----
MANIFEST = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="cc.jeitler.mautg.launcher" version="1.0.0.0"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
'''
grp = struct.pack('<HHH', 0, 1, len(images))
for i, (s, data) in enumerate(images, 1):
    grp += struct.pack('<BBBBHHIH', s % 256, s % 256, 0, 0, 1, 32, len(data), i)

# leaves: (type, id, data)
leaves = [(3, i, d) for i, (_, d) in enumerate(images, 1)] + [(14, 1, grp), (24, 1, MANIFEST)]
types = sorted(set(t for t, _, _ in leaves))

# layout: root dir | type dirs | id dirs (one per leaf, lang level) | data entries | data
def dir_size(n): return 16 + 8 * n
root_off = 0
type_off = {}
cur = dir_size(len(types))
for t in types:
    type_off[t] = cur; cur += dir_size(len([1 for tt, _, _ in leaves if tt == t]))
id_off = {}
for t, i, _ in leaves:
    id_off[(t, i)] = cur; cur += dir_size(1)
de_off = {}
for t, i, _ in leaves:
    de_off[(t, i)] = cur; cur += 16
data_start = (cur + 3) & ~3
data_off = {}
pos = data_start
for t, i, d in leaves:
    data_off[(t, i)] = pos; pos += (len(d) + 3) & ~3
sec = bytearray(pos)
relocs = []
def put_dir(off, entries):
    struct.pack_into('<IIHHHH', sec, off, 0, 0, 0, 0, 0, len(entries))
    for k, (name, target, is_dir) in enumerate(entries):
        struct.pack_into('<II', sec, off + 16 + 8 * k, name, target | (0x80000000 if is_dir else 0))
put_dir(0, [(t, type_off[t], True) for t in types])
for t in types:
    ids = sorted(i for tt, i, _ in leaves if tt == t)
    put_dir(type_off[t], [(i, id_off[(t, i)], True) for i in ids])
for t, i, d in leaves:
    put_dir(id_off[(t, i)], [(0x409, de_off[(t, i)], False)])
    struct.pack_into('<IIII', sec, de_off[(t, i)], data_off[(t, i)], len(d), 0, 0)
    relocs.append(de_off[(t, i)])
    sec[data_off[(t, i)]:data_off[(t, i)] + len(d)] = d

# COFF object (AMD64): header, 1 section, relocations, symbol table
nrel = len(relocs)
sec_hdr_off = 20
raw_off = sec_hdr_off + 40
rel_off = raw_off + len(sec)
sym_off = rel_off + 10 * nrel
coff = struct.pack('<HHIIIHH', 0x8664, 1, 0, sym_off, 1, 0, 0)
coff += struct.pack('<8sIIIIIIHHI', b'.rsrc', 0, 0, len(sec), raw_off, rel_off, 0, nrel, 0, 0x40000040)
coff += bytes(sec)
for r in relocs:
    coff += struct.pack('<IIH', r, 0, 3)          # IMAGE_REL_AMD64_ADDR32NB -> symbol 0
coff += struct.pack('<8sIhHBB', b'.rsrc', 0, 1, 0, 3, 0)   # section symbol
coff += struct.pack('<I', 4)                       # empty string table
# the in-place addend of each ADDR32NB field is the data offset inside the section
c = bytearray(coff)
for r in relocs:
    for (t, i), de in de_off.items():
        if de == r:
            struct.pack_into('<I', c, raw_off + r, data_off[(t, i)])
for d in ('.', '../windows-installer'):
    open(os.path.join(d, 'rsrc_windows_amd64.syso'), 'wb').write(bytes(c))
print('ico', len(ico), 'syso', len(c))
