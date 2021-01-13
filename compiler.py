# CafeLoader Project Compiler
# By Kinnay

import sys, os, shutil, yaml, subprocess, struct
import elftools.elf.elffile
import addrconv
from elf import ELF


# Change the following (use / instead of \)
GHS_PATH = 'D:/Greenhills/ghs/multi5327/'


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


def printUsage():
    print('Usage:')
    print('python compiler.py <project> <version>')

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
        cmd = '"%s" -I ../files/include %s -o objs/%s' %(os.path.join(GHS_PATH, 'asppc.exe'), fn, obj)
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
        self.outdir = 'Out'
        
        files = proj.get('Modules', [])
        self.modules = []
        for fn in files:
            self.modules.append(Module(fn))

    def build(self):
        if not os.path.isdir(self.outdir):
            os.mkdir(self.outdir)

        if not os.path.isdir('objs'):
            os.mkdir('objs')

        self.buildGPJ()
        self.buildGHS()

        if self.objfiles:
            self.link()
            self.copyout()
            if self.genHeader:
                self.buildHeader('Code')

        self.buildPatches()
        self.setAddressBin()

        print('\n' + '=' * 50 + '\n')

    def buildPatches(self):
        patches = {}
        for module in self.modules:
            patches.update(module.getPatches())

        patchdata = struct.pack('>H', len(patches))
        if patches:
            for address, data in patches.items():
                rawaddress = bytes.fromhex(address)
                rawdata = bytes.fromhex(data)
                patchdata += struct.pack('>H', len(rawdata))
                patchdata += rawaddress
                patchdata += rawdata

        with open('Out/Patches.hax', 'wb') as f:
            f.write(patchdata)

    def setAddressBin(self):
        addrdata = struct.pack('>2I', addrconv.symbols['textAddr'], addrconv.symbols['dataAddr'])
        with open('Out/Addr.bin', 'wb') as f:
            f.write(addrdata)

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

        cmd = '"%s" -top project.gpj' %(os.path.join(GHS_PATH, 'gbuild.exe'))
        error = subprocess.call(cmd)
        if error:
            print('Build failed!!')
            print('Error code: %i' %error)
            sys.exit(error)

        self.objfiles = []
        for module in self.modules:
            self.objfiles += module.build()

    def link(self):
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

        cmd = '"%s" %s%s -o "%s" ' %(os.path.join(GHS_PATH, 'elxr.exe'), symfiles, syms, out)
        cmd += ' '.join(self.objfiles)
        error = subprocess.call(cmd)
        if error:
            print('Link Failed!!')
            print('Error code: %i' %error)
            sys.exit(error)

        linker.loadFile(out)

    def copyout(self):
        if self.splitSections:
            self.objcopy(('.text',), 'Code')
            self.objcopy(('.rodata', '.data'), 'Data')
        else:
            raise NotImplementedError

    def objcopy(self, sections, out):
        obj = ELF("%s.o" %self.name)

        outBuffer = bytearray()
        for section in sections:
            sectionObj = obj.getSectionByName(section)
            if sectionObj:
                outBuffer += sectionObj.data

        with open('Out/%s.bin' %out, 'wb') as f:
            f.write(outBuffer)

    def buildHeader(self, binfile):
        with open('Out/%s.bin' %binfile, 'rb') as f:
            data = f.read()

        header = '\nstatic const unsigned char %s_bin[] = {\n ' %binfile
        column = 0
        for byte in data:
            header += ' ' + hex(byte) + ','
            column += 1
            if column == 12:
                column = 0
                header += '\n '
        header = header.rstrip(',\n ')
        header += '\n};\nstatic const unsigned int %s_bin_len = ' %binfile
        header += str(len(data)) + ';\n'
        
        with open('Out/%s.h' %binfile, 'w') as f:
            f.write(header)

def buildProject(proj):
    os.chdir(proj)
    with open('project.yaml') as f:
        project = Project(yaml.safe_load(f))

    project.build()
    os.chdir('..')

def copyOutFiles():
    if not os.path.isdir('OutProj'):
        os.mkdir('OutProj')

    shutil.copy(sys.argv[1]+'/Out/Addr.bin', 'OutProj/Addr.bin')
    shutil.copy(sys.argv[1]+'/Out/Patches.hax', 'OutProj/Patches.hax')
    shutil.copy(sys.argv[1]+'/Out/Code.bin', 'OutProj/Code.bin')
    shutil.copy(sys.argv[1]+'/Out/Data.bin', 'OutProj/Data.bin')

def main():
    if len(sys.argv) < 3:
        printUsage()
        return

    if not os.path.isfile(os.path.join(GHS_PATH, 'gbuild.exe')):
        print("Could not locate MULTI Green Hills Software! Did you set its path?")
        return

    addrconv.loadAddrFile(sys.argv[2])

    global linker
    linker = Linker()
    buildProject(sys.argv[1])

    copyOutFiles()

if __name__ == '__main__':
    main()
