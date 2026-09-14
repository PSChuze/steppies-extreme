import sys, re
# usage: strs.py <file> [minlen]
path = sys.argv[1]
minlen = int(sys.argv[2]) if len(sys.argv) > 2 else 5
data = open(path,'rb').read()
pat = re.compile(rb'[\x20-\x7e]{%d,}' % minlen)
for m in pat.finditer(data):
    print("%08x %s" % (m.start(), m.group().decode('ascii')))
