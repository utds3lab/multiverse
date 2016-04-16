import pwn
pwn.context(os='linux',arch='i386')
import re
import struct

cache = {}
pat = re.compile('\$\+[-]?0x[0-9a-f]+')

#jcxz and jecxz are removed because they don't have a large expansion
JCC = ['jo','jno','js','jns','je','jz','jne','jnz','jb','jnae',
  'jc','jnb','jae','jnc','jbe','jna','ja','jnbe','jl','jnge','jge',
  'jnl','jle','jng','jg','jnle','jp','jpe','jnp','jpo']

#Simple cache code.  Called after more complex preprocessing of assembly source.
def _asm(text):
  if text in cache:
    return cache[text]
  else:
    code = pwn.asm(text)
    cache[text] = code
    return code

def asm(text):
  if '$+' in text:
    code = b''
    for line in text.split('\n'):
      match = pat.search(line)
      if match and match.group() != '$+0x8f':
        #print 'ORIGINAL: %s'%line
        #print 'MATCH %s'%match.group()
        off = int(match.group()[2:],16)
        #print 'offset %x'%off
        line = line.strip()
        mnemonic = line[:line.find(' ')]
        #print 'mnemonic %s'%mnemonic
        #before = _asm(line)
        #print 'BEFORE: %s'%before.encode('hex')
        line = pat.sub('$+0x8f',line) #Replace actual offset with dummy
        newcode = _asm(line) #Assembled code with dummy offset
        #print 'DUMMY: %s'%newcode.encode('hex')
        if mnemonic in ['jmp','call']:
          off-=5 #Subtract 5 because the large encoding knows it's 5 bytes long
          newcode = newcode[0]+struct.pack('<i',off) #Signed int for negative jumps 
        elif mnemonic in JCC:
          off-=6 #Subtract 6 because the large encoding knows it's 6 bytes long
          newcode = newcode[0:2]+struct.pack('<i',off) #Signed int for negative jumps
          #if off < 0:
          #  print 'AFTER: %s'%newcode.encode('hex')
          #  raise Exception
        #print 'AFTER: %s'%newcode.encode('hex')
        #if before != newcode and len(before) != 2:
        #  raise Exception
        code+=newcode
        #raise Exception
      else:
        code+=_asm(line)
    return code
    '''matches = pat.finditer(text)
    start = 0
    for m in matches:
      g = m.group() #entire match
      if g != '' and g != '$+0x8f':
        loc = m.start()
        patches[loc] = g
        prev = text.rfind('\n',loc)
        if prev != -1:
          print text[start:prev]
          start = text.find('\n',loc)
          print '---'
          print text[prev:start]
          print '---'
          print text[start:end]
          print 'ORIGINAL'
          print text
          raise Exception
        print 'OPTIMIZATION OPPORTUNITY: %s'%text'''
  return _asm(text)
