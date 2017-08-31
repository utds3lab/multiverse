import pwn
pwn.context(os='linux',arch='amd64')
import re
import struct

cache = {}
# Metacache stores data about an assembled instruction.
# Specifically, right now it only holds the offset of the
# displacement value (if the instruction encodes a 4-byte displacement).
# This is only used for efficient modification of 
# already-assembled instructions containing a reference to rip.
# This value allows us to change the offset from rip regardless of
# the instruction.
# even if
# there is an immediate value (which appears at the end of an
# encoded instruction's bytes).
metacache = {}
pat = re.compile('\$\+[-]?0x[0-9a-f]+')
pat2 = re.compile('[ ]*push [0-9]+[ ]*')
pat3 = re.compile('[ ]*mov eax, (d)?word ptr \[0x[0-9a-f]+\][ ]*')
pat4 = re.compile('[ ]*mov eax, (dword ptr )?\[(?P<register>e[a-z][a-z])( )?[+-]( )?(0x)?[0-9a-f]+\][ ]*')
pat5 = re.compile('(0x[0-9a-f]+|[0-9]+)')
pat6 = re.compile('[ ]*(?P<mnemonic>(add)|(sub)) (?P<register>(esp)|(ebx)),(?P<amount>[0-9]+)[ ]*')
pat7 = re.compile('[ ]*mov eax, word ptr.*')#Match stupid size mismatch
pat8 = re.compile('[ ]*mov eax, .[xip]')#Match ridiculous register mismatch
rip_with_offset = re.compile(u'\[rip(?: (?P<offset>[\+\-] [0x]?[0-9a-z]+))?\]') #Apparently the hex prefix is optional if the number is...unambiguous?

#jcxz and jecxz are removed because they don't have a large expansion
JCC = ['jo','jno','js','jns','je','jz','jne','jnz','jb','jnae',
  'jc','jnb','jae','jnc','jbe','jna','ja','jnbe','jl','jnge','jge',
  'jnl','jle','jng','jg','jnle','jp','jpe','jnp','jpo']

#Simple cache code.  Called after more complex preprocessing of assembly source.
def _asm(text):
  if text in cache:
    return cache[text]
  else:
    with open('uncached.txt','a') as f:
      f.write(text+'\n')
    code = pwn.asm(text)
    cache[text] = code
    return code

def asm(text):
  code = b''
  for line in text.split('\n'):
    if not line.find(';') == -1:
      line = line[:line.find(';')]#Eliminate comments
    #Check for offsets ($+)
    match = pat.search(line)
    if match and match.group() != '$+0x8f':
      off = int(match.group()[2:],16)
      line = line.strip()
      mnemonic = line[:line.find(' ')]
      line = pat.sub('$+0x8f',line) #Replace actual offset with dummy
      newcode = _asm(line) #Assembled code with dummy offset
      if mnemonic in ['jmp','call']:
        off-=5 #Subtract 5 because the large encoding knows it's 5 bytes long
        newcode = newcode[0]+struct.pack('<i',off) #Signed int for negative jumps 
      elif mnemonic in JCC:
        off-=6 #Subtract 6 because the large encoding knows it's 6 bytes long
        newcode = newcode[0:2]+struct.pack('<i',off) #Signed int for negative jumps
      code+=newcode
    #Check for push instruction
    elif pat2.match(line):
      code+=b'\x68' + struct.pack('<I',int(line.strip().split(' ')[1]) ) #push case
    #Check for mov instruction to eax from immediate
    elif pat3.match(line):
      #mov eax, dword ptr [0xcafecafe]
      if ' word' in line:
        print 'WARNING: silently converting "mov eax, word ptr [<number>]" to "mov eax, dword ptr [<number>]"'
      code+=b'\xa1' + struct.pack('<I',int(line[line.find('[')+1:line.find(']')],16) )
    #Check for mov instruction to eax from some register plus or minus an offset
    #NOTE: This does NOT WORK for esp!  The instruction encoding pattern is DIFFERENT!
    #To handle this, right now this will only replace e[a-z]x registers, although it 
    #seems as if esi,edi, or ebp would also work.
    elif pat4.match(line):
      m = pat4.match(line)
      #f = open('crazyq.txt','a')
      #f.write(line+'\n')
      #ocode = _asm(line)
      #f.write(str(ocode).encode('hex')+'\n')
      original = pat5.search(line).group()
      if original.startswith('0x'):
        original = int(original,16)
      else:
        original = int(original)
      if '-' in line:
        original=-original
      if abs(original) > 0x7f:
        line = pat5.sub('0x8f',line)
        original = struct.pack('<i',original)
      else:
        line = pat5.sub('0x7f',line)
        original = struct.pack('<b',original)
      newcode = _asm(line)
      #f.write(str(newcode).encode('hex')+'\n')
      if m.group('register') == 'esp':
        newcode = newcode[0:3]+original
      else:
        newcode = newcode[0:2]+original
      #f.write(str(newcode).encode('hex')+'\n')
      #if newcode != ocode:
      #  print 'NO MATCH %s:\n%s\n%s'%(line,newcode.encode('hex'),ocode.encode('hex'))
      #  raise Exception
      #f.close() 
      code+=newcode
    elif pat6.match(line):
      print 'WARNING: Using assumption to efficiently assemble "%s"' % line
      #ocode = _asm(line)
      m = pat6.match(line)
      amount = int(m.group('amount'))
      register = m.group('register')
      mnemonic = m.group('mnemonic')
      if amount > 0x7f:
        newcode = _asm('%s %s,0x8f'%(mnemonic,register) )
        newcode = newcode[:2] + struct.pack('<i',amount)
      else:
        newcode = _asm('%s %s,0x7f'%(mnemonic,register) )
        newcode = newcode[:2] + struct.pack('<b',amount)
      #if newcode != ocode:
      #  print 'NO MATCH %s:\n%s\n%s'%(line,newcode.encode('hex'),ocode.encode('hex'))
      #  raise Exception
      code+=newcode
    elif pat7.match(line):
      print 'WARNING: silently converting "mov eax, word ptr [<value>]" to "mov eax, dword ptr [<value>]"'
      code+=_asm(line.replace(' word',' dword'))
    elif pat8.match(line):
      print 'WARNING: silently converting "mov eax, <letter>[xip]" to "mov eax, e<letter>[xip]"'
      code+=_asm(line.replace(', ',', e'))
    elif rip_with_offset.search(line):
      #print 'WARNING: using assumption to efficiently assemble "%s"' % line
      m = rip_with_offset.search(line)
      newstr = rip_with_offset.sub('[rip]', line)
      if newstr in metacache:
        # Assemble it with no offset, which must have have already been added to the cache
        newcode = _asm( newstr )
        if m.group('offset'):
          #immediate = newcode[-metacache[newstr]:] if newstr in metacache else b''
          #print 'WARNING: using assumption to efficiently assemble "%s"' % line
          # Replace 4 bytes of displacement with little-endian encoded offset retrieved from the original assembly
          #code += newcode[:-(4+len(immediate))] + struct.pack( '<i', int(m.group('offset'),16) ) + immediate
          code += newcode[:metacache[newstr]] + struct.pack( '<i', int(m.group('offset'),16) ) + newcode[metacache[newstr]+4:]
        else:
          code += newcode
      else:
        code+=_asm(line) # if we don't have it properly cached, just assemble the original
    else:
      code+=_asm(line)
  return code
