# ELFLib - A library for reading/writing common ELF files
# Made by AboodXD

# Currently specifically targeted at "uncompressed" RPL files (ELF files which were originally RPL files)
# (Hence why program headers are not supported yet)
# http://wiiubrew.org/wiki/RPL

import struct


def readString(data, offset=0, charWidth=1, encoding='utf-8'):
    end = data.find(b'\0' * charWidth, offset)
    if end == -1:
        return data[offset:].decode(encoding)

    return data[offset:end].decode(encoding)


def round_up(x, y):
    return ((x - 1) | (y - 1)) + 1


class ELF:
    class _SectionHeader(struct.Struct):
        def __init__(self, data, offset, format_, rela):
            super().__init__(format_)

            (self.nameIdx,
             self.type,
             self.flags,
             self.vAddr,
             self.offset,
             self.size_,
             self.link,
             self.info,
             self.addrAlign,
             self.entSize) = self.unpack_from(data, offset)

            self.isStrTable = self.type == 3
            if self.isStrTable:
                if self.entSize > 1:
                    raise NotImplementedError("Character sizes above 1 byte are not supported yet.")

                assert data[self.offset] == 0

            self.relocations = []  # Only used for .rela sections

            if self.type == 8:
                self.data = bytearray(self.size_)

            else:
                self.data = bytearray(data[self.offset:self.offset + self.size_])

                if self.type == 4:
                    self.loadRela(rela, format_[0])

            self.name = 'None'

        def loadRela(self, rela, endian):
            count = len(self.data) // self.entSize
            self.relocations = []
            for i in range(count):
                self.relocations.append(rela(self.data, i * self.entSize, endian))

        def saveRela(self):
            self.data = bytearray(b''.join([rela.save() for rela in self.relocations]))

        def readName(self, shStrTable):
            if self.nameIdx:
                self.name = readString(shStrTable.data, self.nameIdx)

        def printInfo(self):
            types = {
                0: 'SHT_NULL', 1: 'SHT_PROGBITS', 2: 'SHT_SYMTAB', 3: 'SHT_STRTAB',
                4: 'SHT_RELA', 5: 'SHT_HASH', 6: 'SHT_DYNAMIC', 7: 'SHT_NOTE',
                8: 'SHT_NOBITS', 9: 'SHT_REL', 10: 'SHT_SHLIB', 11: 'SHT_DYNSYM',
                14: 'SHT_INIT_ARRAY', 15: 'SHT_FINI_ARRAY', 16: 'SHT_PREINIT_ARRAY',
                17: 'SHT_GROUP', 18: 'SHT_SYMTAB_SHNDX',
                0x60000000: 'SHT_LOOS',
                0x6fffffff: 'SHT_HIOS',
                0x70000000: 'SHT_LOPROC',
                0x7fffffff: 'SHT_HIPROC',
                0x80000000: 'SHT_LOUSER',
                0x80000001: 'SHT_RPL_EXPORTS',
                0x80000002: 'SHT_RPL_IMPORTS',
                0x80000003: 'SHT_RPL_CRCS',
                0x80000004: 'SHT_RPL_FILEINFO',
                0xffffffff: 'SHT_HIUSER',
            }

            print("\nName:", self.name)

            if self.type in types:
                print("Type:", types[self.type])

            else:
                print("Type:", hex(self.type))

            print("Flags:", hex(self.flags))
            print("Virual Address:", hex(self.vAddr))
            print("Offset:", hex(self.offset))
            print("Section Size:", hex(self.size_))
            print("Linked section index:", self.link)
            print("Extra info:", hex(self.info))
            print("Section Alignment:", hex(self.addrAlign))
            print("Section Entry Size:", hex(self.entSize))

        def save(self, offset):
            if self.type == 8:
                offset = 0

            elif self.type == 4:
                self.saveRela()

            return struct.pack(
                self.format,
                self.nameIdx,
                self.type,
                self.flags,
                self.vAddr,
                offset,
                len(self.data),
                self.link,
                self.info,
                self.addrAlign,
                self.entSize
            )

    class SectionHeader32(_SectionHeader):
        def __init__(self, data, offset, endian):
            super().__init__(data, offset, '%s10I' % endian, ELF.Rela32)

    class SectionHeader64(_SectionHeader):
        def __init__(self, data, offset, endian):
            super().__init__(data, offset, '%s2I4Q2I2Q' % endian, ELF.Rela64)

    class _Rela(struct.Struct):
        def __init__(self, data, offset, format_):
            super().__init__(format_)

            (self.offset,
             self.info,
             self.addend) = self.unpack_from(data, offset)

        def save(self):
            return struct.pack(
                self.format,
                self.offset,
                self.info,
                self.addend,
            )

    class Rela32(_Rela):
        def __init__(self, data, offset, endian):
            super().__init__(data, offset, '%s2Ii' % endian)

    class Rela64(_Rela):
        def __init__(self, data, offset, endian):
            super().__init__(data, offset, '%s2Qq' % endian)

    class Header(struct.Struct):
        class Identifier(struct.Struct):
            def __init__(self, data):
                super().__init__('=4s5B7x')

                (self.magic,
                 self.class_,
                 self.enc,
                 self.version,
                 self.osAbi,
                 self.abiVersion) = self.unpack_from(data, 0)

                self.checkIdentifier()

            def checkIdentifier(self):
                assert self.magic == b'\x7FELF'
                assert self.class_ in (1, 2)
                assert self.enc in (1, 2)
                assert self.version == 1

            def save(self):
                return struct.pack(
                    '=4s5B7x',
                    self.magic,
                    self.class_,
                    self.enc,
                    self.version,
                    self.osAbi,
                    self.abiVersion,
                )

        def __init__(self, data):
            self.ident = self.Identifier(data); pos = self.ident.size
            self.endian = '<' if self.ident.enc == 1 else '>'
            uintF = 'I' if self.ident.class_ == 1 else 'Q'

            super().__init__('%s2HI3%sI6H' % (self.endian, uintF))

            (self.type,
             self.machine,
             self.version,
             self.entry,
             self.progHeadOff,
             self.secHeadOff,
             self.flags,
             self.size_,
             self.progHeadEntSize,
             self.progHeadNum,
             self.secHeadEntSize,
             self.secHeadNum,
             self.namesSecHeadIdx) = self.unpack_from(data, pos)

            self.checkHeader()

        def checkHeader(self):
            assert self.version == 1
            assert self.size_ == self.size + self.ident.size

        def printInfo(self):
            print("Endianness:", self.endian)
            print("OS ABI:", hex((self.ident.osAbi) << 8 | self.ident.abiVersion))

            types = {
                0x00: 'ET_NONE', 0x01: 'ET_REL', 0x02: 'ET_EXEC',
                0x03: 'ET_DYN', 0x04: 'ET_CORE', 0xfe00: 'ET_LOOS',
                0xfeff: 'ET_HIOS', 0xff00: 'ET_LOPROC', 0xffff: 'ET_HIPROC',
            }

            if self.type in types:
                print("Type:", types[self.type])

            else:
                print("Type:", hex(self.type))

            machines = {
                0x14: 'PowerPC',
            }

            if self.machine in machines:
                print("ISA:", machines[self.machine])

            else:
                print("ISA:", hex(self.machine))

            print("Entry point:", hex(self.entry))

            if self.progHeadOff >= self.size_:
                print("Program Header Offset:", hex(self.progHeadOff))
                print("Program Header Entries Count:", self.progHeadNum)
                print("Program Header Entry Size:", hex(self.progHeadEntSize))

            if self.secHeadOff >= self.size_ and self.secHeadOff != self.progHeadOff:
                print("Section Header Offset:", hex(self.secHeadOff))
                print("Section Header Entries Count:", self.secHeadNum)
                print("Section Header Entry Size:", hex(self.secHeadEntSize))

        def save(self, secHeadEnts):
            outBuffer = bytearray(self.ident.save())

            namesSecHeadIdx = 0
            for i, entry in enumerate(secHeadEnts):
                if entry.name == '.shstrtab':
                    namesSecHeadIdx = i
                    break

            size = self.size + self.ident.size
            outBuffer += struct.pack(
                self.format,
                self.type,
                self.machine,
                self.version,
                self.entry,
                0,  # TODO: Program headers
                round_up(size, 0x10),
                self.flags,
                size,
                0,
                0,
                secHeadEnts[0].size,
                len(secHeadEnts),
                namesSecHeadIdx,
            )

            return outBuffer

    def __init__(self, file):
        with open(file, "rb") as inf:
            inb = inf.read()

        self.header = self.Header(inb); pos = self.header.size_

        self.progHeadEnts = []
        self.secHeadEnts = []
        self.shStrTable = None

        if self.header.progHeadOff >= self.header.size_:
            pos = self.header.progHeadOff  # TODO

        if self.header.secHeadOff >= self.header.size_ and self.header.secHeadOff != self.header.progHeadOff:
            pos = self.header.secHeadOff

            for i in range(self.header.secHeadNum):
                if self.header.ident.class_ == 1:
                    entry = ELF.SectionHeader32(inb, pos, self.header.endian)

                else:
                    entry = ELF.SectionHeader64(inb, pos, self.header.endian)

                if i == self.header.namesSecHeadIdx:
                    assert entry.isStrTable
                    self.shStrTable = entry

                self.secHeadEnts.append(entry); pos += self.header.secHeadEntSize

        for entry in self.secHeadEnts:
            if self.shStrTable:
                entry.readName(self.shStrTable)

        #self.printInfo()

    def printInfo(self):
        self.header.printInfo()

        for i, entry in enumerate(self.secHeadEnts[1:]):
            print("Section %d" % (i+1))
            entry.printInfo()

    def getSectionByName(self, name):
        for entry in self.secHeadEnts:
            if entry.name == name:
                return entry

        return None

    def save(self):
        self.header.type = 0xFE01
        outBuffer = bytearray(self.header.save(self.secHeadEnts))

        align = round_up(len(outBuffer), 0x10) - len(outBuffer)
        outBuffer += b'\0' * align

        # TODO: Program headers
        offset = self.header.size + self.header.ident.size + align + len(self.secHeadEnts) * self.secHeadEnts[0].size
        outBuffer += self.secHeadEnts[0].save(0)
        for entry in self.secHeadEnts[1:]:
            outBuffer += entry.save(offset)
            if entry.type != 8:
                offset += len(entry.data)

        for entry in self.secHeadEnts:
            if entry.type != 8:
                outBuffer += entry.data

        return outBuffer
