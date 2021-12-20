
def round_up(x, y):
    return ((x - 1) | (y - 1)) + 1

symbols = {}
diffs = []

def parseAddrFile(lines):
    global text, data, textAddr, dataAddr
    for line in lines:
        line = line.strip().replace(' ', '')

        if not line or line.startswith('#'):
            pass

        elif line.startswith('text='): text = eval(line.split('text=')[1])
        elif line.startswith('data='): data = eval(line.split('data=')[1])
        
        elif line.startswith('-'):
            symentry = line.split('=')
            symbol, address = symentry[0][1:], eval(symentry[1])
            symbols[symbol] = address

        else:
            old, new = line.split(':Addr')
            starthex, endhex = old.split('-')
            start = int(starthex, 16)
            end = int(endhex, 16)
            diff = eval(new)
            diffs.append((start, end, diff))

    symbols['textAddr'] = round_up(symbols['textAddr'], 32)
    symbols['dataAddr'] = round_up(symbols['dataAddr'] + 4, 32)
    assert symbols['textAddr'] < symbols['dataAddr']

def loadAddrFile(name):
    global region
    region = name
    
    symbols.clear()
    del diffs[:]

    with open('addr_%s.txt' %name) as f:
        parseAddrFile(f.readlines())

def convert(address, fixWriteProtection=False):
    if address < 0x10000000:
        segment = text
    else:
        segment = data

    for diff in diffs:
        if diff[0] <= address < diff[1]:
            addr = address + diff[2] + segment
            return addr

    raise ValueError("Invalid or unimplemented address: 0x%x" %address)

def removeCComments(file_str):
    file_len = len(file_str)
    res = bytearray()

    # https://stackoverflow.com/a/2395019

    pos = 0
    while pos < file_len:
        c = file_str[pos]
        if c == '\'' or c == '"':
            q = c
            while True:
                res += c.encode()
                if c == '\\':
                    pos += 1
                    res += file_str[pos].encode()
                pos += 1
                c = file_str[pos]
                if c == q:
                    break
            res += c.encode()
        elif c == '/':
            pos += 1
            c = file_str[pos]
            if c != '*':
                res += b'/'
                pos -= 1
            else:
                res += b' '
                while True:
                    p = c
                    pos += 1
                    c = file_str[pos]
                    if c == '/' and p == '*':
                        break
        else:
            res += c.encode()
        pos += 1

    return res.decode()

def convertTable(oldfile, newfile):
    with open(oldfile) as f:
        lines = f.readlines()

    lines = removeCComments(''.join(lines)).split('\n')

    newlines = []
    for line in lines:
        if '//' in line:
            eol_comment_pos = line.find('//')
            line = line[:eol_comment_pos]

        line = line.strip()
        
        if line[-1:] == ';':
            name, addr = line[:-1].split('=')
            name = name.strip()
            addr = addr.strip()

            if name == '__deleted_virtual_called':
                __deleted_virtual_called = eval(addr)
            
            newaddr = convert(eval(addr))
            newlines.append('%s = 0x%x;\n' %(name, newaddr))
        else:
            newlines.append(line+'\n')

    with open(newfile, 'w') as f:
        f.writelines(newlines)
