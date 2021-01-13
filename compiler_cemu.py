# CafeLoader Project Compiler (Cemu Edition)
# With help from Kinnay and Exzap

import copy, sys, os, shutil, yaml, subprocess, struct
import elftools.elf.elffile
import addrconv_cemu as addrconv
from elf import ELF, round_up


# Change the following (use / instead of \)
GHS_PATH = 'D:/Greenhills/ghs/multi5327/'
wiiurpxtool = 'D:/NSMBU RE/v1.3.0/code/wiiurpxtool.exe'


TEMPLATE = """#!gbuild
primaryTarget=ppc_standalone.tgt
[Project]
\t-bsp generic
\t-cpu=espresso
\t-object_dir=objs
\t-Ospeed
\t--g++
\t--no_debug
\t--no_rtti
\t-Omemfuncs
\t-Ostrfuncs
\t-DCemu
\t-DREGION_%s
\t-DCODE_ADDR=0x%x
\t-DDATA_ADDR=0x%x
\t-I%s
%s
"""

SymTableTemplate = """
MEMORY 
{
    codearea : origin = %s, length = %s
    dataarea : origin = %s, length = %s
}

OPTION("-append")

SECTIONS 
{
    .text : > codearea
    .rodata : > dataarea
    .data : > dataarea
    .bss : > dataarea
}"""

project = None
buildAsRelocatable = False


def printUsage():
    print('Usage:')
    print('python compiler.py <project directory> <version> <rpx file>')

class Linker:
    def loadFile(self, filename):
        f = open(filename, 'rb')
        self.elf = elftools.elf.elffile.ELFFile(f)
        self.loadSymbols()
        f.close()

    def loadSymbols(self):
        self.symbols = {}
        sections = list(self.elf.iter_sections())
        symtable = self.elf.get_section_by_name('.symtab')
        
        for symbol in symtable.iter_symbols():
            if not symbol.name: continue
            
            entry = symbol.entry
            value = entry['st_value']
            shndx = entry['st_shndx']

            if shndx in ['SHN_ABS', 'SHN_UNDEF']: continue
            
            section = sections[shndx]
            if section.name != '.text': continue

            self.symbols[symbol.name] = value

    def getSymbol(self, name):
        return self.symbols[name]

    def doB(self, symbol, src):
        symaddr = self.getSymbol(symbol)
        instr = (symaddr - src) & 0x03FFFFFC
        instr |= 0x48000000
        return "%x" %instr

    def doBL(self, symbol, src):
        symaddr = self.getSymbol(symbol)
        instr = (symaddr - src) & 0x03FFFFFC
        instr |= 0x48000001
        return "%x" %instr

class Module:
    def __init__(self, fn):
        self.name = os.path.splitext(fn)[0]
        with open(fn) as f:
            module = yaml.safe_load(f)

        self.codefiles = module.get('Files', [])
        self.hooks = module.get('Hooks', [])

    def build(self):
        self.objfiles = []
        for codefile in self.codefiles:
            if codefile.endswith('.cpp'):
                self.objfiles.append('objs/%s' %os.path.basename(os.path.splitext(codefile)[0]+'.o'))
            if codefile.endswith('.S'):
                self.buildAsm(codefile)
        return self.objfiles

    def buildAsm(self, fn):
        print("Assembling '%s'" %fn)
        obj = os.path.basename(fn+'.o')
        cmd = '"%s" -I ../files/include %s -o objs/%s' %(os.path.join(GHS_PATH, 'asppc'), fn, obj)
        error = subprocess.call(cmd)
        if error:
            print('Build failed!!')
            print('Error code: %i' %error)
            sys.exit(error)
        self.objfiles.append('objs/%s' %obj)

    def getPatches(self):
        patchList = {}
        for hook in self.hooks:
            hooktype = hook['type']
            addr = int(hook['addr'], 16)
            
            if hooktype == 'patch':
                addr = addrconv.convert(addr, True)
                patchList['%08x' %addr] = hook['data']

            elif hooktype == 'nop':
                addr = addrconv.convert(addr, True)
                patchList['%08x' %addr] = '60000000'

            elif hooktype == 'branch':
                addr = addrconv.convert(addr)
                if hook['instr'] == 'b':
                    data = linker.doB(hook['func'], addr)
                elif hook['instr'] == 'bl':
                    data = linker.doBL(hook['func'], addr)

                patchList['%08x' %addr] = data

            elif hooktype == 'funcptr':
                addr = addrconv.convert(addr)
                patchList['%08x' %addr] = '%08x' %linker.getSymbol(hook['func'])

        return patchList

class Project:
    def __init__(self, proj):
        self.splitSections = proj.get('SplitSections', True)
        self.genHeader = proj.get('BuildHeader', False)
        self.include = proj.get('Include', None)
        self.name = proj['Name']
        
        files = proj.get('Modules', [])
        self.modules = []
        for fn in files:
            self.modules.append(Module(fn))

    def build(self):
        if buildAsRelocatable and self.objfiles:
            self.link()
            print('\n' + '=' * 50 + '\n')

            return

        if not os.path.isdir('objs'):
            os.mkdir('objs')

        self.buildGPJ()
        self.buildGHS()

        if self.objfiles:
            self.link()

        print('\n' + '=' * 50 + '\n')

    def buildGPJ(self):
        fileList = ''
        for module in self.modules:
            for fn in module.codefiles:
                fileList += fn + '\n'

        include = '../files/include'
        if self.include:
            include += '\n\t-I%s' %self.include

        template = TEMPLATE %(
            addrconv.region,
            addrconv.symbols['textAddr'],
            addrconv.symbols['dataAddr'],
            include,
            fileList.strip()
            )

        with open('project.gpj', 'w') as f:
            f.write(template)

    def buildGHS(self):
        print("*** Building '%s' ***\n" %self.name)

        cmd = '"%s" -top project.gpj' %(os.path.join(GHS_PATH, 'gbuild'))
        error = subprocess.call(cmd)
        if error:
            print('Build failed!!')
            print('Error code: %i' %error)
            sys.exit(error)

        self.objfiles = []
        for module in self.modules:
            self.objfiles += module.build()

    def link(self):
        if buildAsRelocatable:
            print("Linking '%s' as relocatable" %self.name)

        else:
            print("Linking '%s'" %self.name)

        symtable = '../files/game_%s.x' %addrconv.region
        addrconv.convertTable('../files/game.x', symtable)
        
        out = self.name + '.o'
        symfiles = '-T %s' %symtable

        textAddr = addrconv.symbols['textAddr']
        dataAddr = addrconv.symbols['dataAddr']

        with open("project.ld", "w+") as symfile:
            symfile.write(SymTableTemplate % (
                hex(textAddr),
                hex(0x10000000 - textAddr),
                hex(dataAddr),
                hex(0xC0000000 - dataAddr),
            ))

        symfiles += ' -T project.ld'

        syms = ''
        for sym, addr in addrconv.symbols.items():
            syms += ' -D%s=0x%x' %(sym, addr)

        if buildAsRelocatable:
            cmd = '"%s" -r %s%s -o "%s" ' %(os.path.join(GHS_PATH, 'elxr'), symfiles, syms, out)

        else:
            cmd = '"%s" %s%s -o "%s" ' %(os.path.join(GHS_PATH, 'elxr'), symfiles, syms, out)

        cmd += ' '.join(self.objfiles)
        error = subprocess.call(cmd)
        if error:
            print('Link Failed!!')
            print('Error code: %i' %error)
            sys.exit(error)

        linker.loadFile(out)

def buildProject(proj):
    os.chdir(proj)

    global project
    with open('project.yaml') as f:
        project = Project(yaml.safe_load(f))

    project.build()
    os.chdir('..')

def patchRpx(proj, rpx):
    print("Decompressing RPX...")
    elfName = '%s.elf' % os.path.splitext(rpx)[0]
    rpxName = '%s_2.rpx' % os.path.splitext(rpx)[0]

    elfName2 = os.path.join(proj, '%s.o' % project.name)

    DETACHED_PROCESS = 0x00000008
    subprocess.call('"%s" -d "%s" "%s"' % (wiiurpxtool, rpx, elfName), creationflags=DETACHED_PROCESS)

    assert os.path.isfile(elfName)

    print("Loading ELF...")
    elfObj = ELF(elfName)

    print("Loading hax ELF...")
    haxObj = ELF(elfName2)

    rplFileInfo = elfObj.secHeadEnts.pop()
    rplCRCs = elfObj.secHeadEnts.pop()

    text = haxObj.getSectionByName('.text'); assert text is not None
    rodata = haxObj.getSectionByName('.rodata')
    data = haxObj.getSectionByName('.data')
    bss = haxObj.getSectionByName('.bss')
    symtab = haxObj.getSectionByName('.symtab')
    strtab = haxObj.getSectionByName('.strtab')

    patches = {}
    for module in project.modules:
        patches.update(module.getPatches())

    # TODO: relocations
    # Current Cemu version let's us get away
    # with not doing add relocations, but
    # Exzap said it's not guaranteed to stay that way
    """
    global buildAsRelocatable
    buildAsRelocatable = True

    os.chdir(proj)
    project.build()
    os.chdir('..')

    haxObj = ELF(elfName2)
    """

    rela_text = haxObj.getSectionByName('.rela.text')
    rela_rodata = haxObj.getSectionByName('.rela.rodata')
    rela_data = haxObj.getSectionByName('.rela.data')

    #shStrBase = len(elfObj.shStrTable.data)

    text.nameIdx = 0  # shStrBase; elfObj.shStrTable.data += b'.textHaxx\0'; shStrBase += 10
    elfObj.secHeadEnts.append(text)
    text.flags = elfObj.getSectionByName('.text').flags

    if rela_text:
        rela_text.nameIdx = 0  # shStrBase; elfObj.shStrTable.data += b'.rela.textHaxx\0'; shStrBase += 15
        elfObj.secHeadEnts.append(rela_text)
        rela_text.flags = elfObj.getSectionByName('.rela.text').flags

    if rodata:
        rodata.nameIdx = 0  # shStrBase; elfObj.shStrTable.data += b'.rodataHaxx\0'; shStrBase += 12
        elfObj.secHeadEnts.append(rodata)
        rodata.flags = elfObj.getSectionByName('.rodata').flags

    if rela_rodata:
        rela_rodata.nameIdx = 0  # shStrBase; elfObj.shStrTable.data += b'.rela.rodataHaxx\0'; shStrBase += 17
        elfObj.secHeadEnts.append(rela_rodata)
        rela_rodata.flags = elfObj.getSectionByName('.rela.rodata').flags

    if data:
        data.nameIdx = 0  # shStrBase; elfObj.shStrTable.data += b'.dataHaxx\0'; shStrBase += 10
        elfObj.secHeadEnts.append(data)
        data.flags = elfObj.getSectionByName('.data').flags

    if rela_data:
        rela_data.nameIdx = 0  # shStrBase; elfObj.shStrTable.data += b'.rela.dataHaxx\0'; shStrBase += 15
        elfObj.secHeadEnts.append(rela_data)
        rela_data.flags = elfObj.getSectionByName('.rela.data').flags

    if bss:
        bss.nameIdx = 0  # shStrBase; elfObj.shStrTable.data += b'.bssHaxx\0'; shStrBase += 9
        elfObj.secHeadEnts.append(bss)
        bss.flags = elfObj.getSectionByName('.bss').flags

    if symtab:
        symtab.nameIdx = 0  # shStrBase; elfObj.shStrTable.data += b'.symtabHaxx\0'; shStrBase += 12
        elfObj.secHeadEnts.append(symtab)
        symtab.flags = elfObj.getSectionByName('.symtab').flags

        symtab.vAddr = round_up(addrconv.symbols['symsAddr'], symtab.addrAlign)

    if strtab:
        strtab.nameIdx = 0  # shStrBase; elfObj.shStrTable.data += b'.strtabHaxx\0'; shStrBase += 12
        elfObj.secHeadEnts.append(strtab)
        strtab.flags = elfObj.getSectionByName('.strtab').flags

        if symtab:
            strtab.vAddr = round_up(addrconv.symbols['symsAddr'] + len(symtab.data), strtab.addrAlign)

        else:
            strtab.vAddr = round_up(addrconv.symbols['symsAddr'], strtab.addrAlign)

    dataSections = []
    if rodata:
        dataSections.append(rodata)

    if data:
        dataSections.append(data)

    if bss:
        dataSections.append(bss)

    dataSections = sorted(dataSections, key=lambda a: a.vAddr)

    rplFileInfo.data[4:8] = struct.pack('>I', int.from_bytes(rplFileInfo.data[4:8], 'big') + len(text.data))
    if dataSections:
        rplFileInfo.data[12:16] = struct.pack('>I', int.from_bytes(rplFileInfo.data[12:16], 'big') + dataSections[-1].vAddr - addrconv.symbols['dataAddr'] + len(dataSections[-1].data))

    elfObj.secHeadEnts.append(rplCRCs)
    elfObj.secHeadEnts.append(rplFileInfo)

    if rela_text:
        if symtab:
            rela_text.link = elfObj.secHeadEnts.index(symtab)

        rela_text.info = elfObj.secHeadEnts.index(text)

        for rela in rela_text.relocations:
            if rela.offset < text.vAddr:
                rela.offset += text.vAddr

    if rodata and rela_rodata:
        if symtab:
            rela_rodata.link = elfObj.secHeadEnts.index(symtab)

        rela_rodata.info = elfObj.secHeadEnts.index(rodata)

        for rela in rela_rodata.relocations:
            if rela.offset < rodata.vAddr:
                rela.offset += rodata.vAddr

    if data and rela_data:
        if symtab:
            rela_data.link = elfObj.secHeadEnts.index(symtab)

        rela_data.info = elfObj.secHeadEnts.index(data)

        for rela in rela_data.relocations:
            if rela.offset < data.vAddr:
                rela.offset += data.vAddr

    if symtab and strtab:
        symtab.link = elfObj.secHeadEnts.index(strtab)

    print("Applying patches...")
    if patches:
        oText = elfObj.getSectionByName('.text')
        oRelaText = elfObj.getSectionByName('.rela.text')

        oRoData = elfObj.getSectionByName('.rodata')
        oRelaRoData = elfObj.getSectionByName('.rela.rodata')

        oData = elfObj.getSectionByName('.data')
        oRelaData = elfObj.getSectionByName('.rela.data')

        oBss = elfObj.getSectionByName('.bss')

        for address, data in patches.items():
            address = int(address, 16)
            rawdata = bytes.fromhex(data)

            if oText.vAddr <= address < addrconv.symbols['textAddr']:
                toPatch = oText
                oRela = oRelaText

            elif min(oRoData.vAddr, oData.vAddr, oBss.vAddr) <= address < addrconv.symbols['dataAddr']:
                if oRoData.vAddr <= address < oRoData.vAddr + len(oRoData.data):
                    toPatch = oRoData
                    oRela = oRelaRoData

                elif oData.vAddr <= address < oData.vAddr + len(oData.data):
                    toPatch = oData
                    oRela = oRelaData

                elif oBss.vAddr <= address < oBss.vAddr + len(oBss.data):
                    print("Patching .bss is not possible.")
                    print("Skipping patch at %s" % hex(address))
                    continue

                else:
                    print("Patch at unknown region.")
                    print("Skipping patch at %s" % hex(address))
                    continue

            else:
                print("Patch at unknown region.")
                print("Skipping patch at %s" % hex(address))
                continue

            toRemove = -1

            for i, rela in enumerate(oRela.relocations):
                if rela.offset in [address + i for i in range(len(rawdata))]:
                    print("Found relocation at %s. Removing..." % hex(rela.offset))
                    toRemove = i
                    break

            if toRemove != -1:
                del oRela.relocations[toRemove]

            addr = address - toPatch.vAddr
            toPatch.data[addr:addr + len(rawdata)] = rawdata
            print("Patched %d bytes at %s" % (len(rawdata), hex(address)))

    print("Saving ELF...")
    buf = elfObj.save()
    with open(elfName, 'wb') as out:
        out.write(buf)

    print("Compressing RPX...")
    DETACHED_PROCESS = 0x00000008
    subprocess.call('"%s" -c "%s" "%s"' % (wiiurpxtool, elfName, rpxName), creationflags=DETACHED_PROCESS)

    os.remove(elfName)

    print('\n' + '=' * 50 + '\n')

def main():
    if len(sys.argv) < 3:
        printUsage()
        return

    if not os.path.isfile(os.path.join(GHS_PATH, 'gbuild.exe')):
        print("Could not locate MULTI Green Hills Software! Did you set its path?")
        return

    addrconv.loadAddrFile(sys.argv[2])

    global linker, buildAsRelocatable
    linker = Linker()
    buildProject(sys.argv[1])

    if not os.path.isfile(wiiurpxtool):
        print("Could not locate wiiurpxtool.exe! Did you set its path?")
        return

    rpx = sys.argv[3]
    if not os.path.isfile(rpx):
        print("Could not locate the RPX file to patch! Did you correctly enter its path?")
        return

    patchRpx(sys.argv[1], rpx)

if __name__ == '__main__':
    main()
