import pwn
pwn.context(os='linux',arch='i386')
import re
import struct

cache = {}
pat = re.compile('\$\+[-]?0x[0-9a-f]+')
pat2 = re.compile('[ ]*push [0-9]+[ ]*')
pat3 = re.compile('mov eax, dword ptr \[0x[0-9a-f]+\]')

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
      elif pat2.match(line):
        #print 'push 02'
        code+=b'\x68' + struct.pack('<I',int(line.strip().split(' ')[1]) ) #push case
      else:
        code+=_asm(line)
    return code
  elif pat2.match(text):
    #print 'push 01'
    #since this is always the push instruction, there really is no need to call pwn.asm at all.
    return b'\x68' + struct.pack('<I',int(text.strip().split(' ')[1]) )
    #print str(pwn.asm(text)).encode('hex')
    #print str(pwn.asm('push 0x8f')).encode('hex')
  #TODO: use this for optimizations, but also include other instructions outside of match
  #match = pat3.search(text)
  #if match:
  #  inst = match.group()
  #  return b'\xa1' + struct.pack('<I',int(inst[inst.find('[')+1:-1],16) ) #mov eax, dword ptr [0xcafecafe]
  #  #print str(pwn.asm(inst)).encode('hex')
  #  #print str(pwn.asm('mov eax, dword ptr [0x8f]')).encode('hex')
  #  #print hex(int(inst[inst.find('[')+1:-1],16))
  #  #print (  b'\xa1' + struct.pack('<I',int(inst[inst.find('[')+1:-1],16) )   ).encode('hex')
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
