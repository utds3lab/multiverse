import pwn
pwn.context(os='linux',arch='amd64')
import re
import struct

cache = {}
pat = re.compile('\$\+[-]?0x[0-9a-f]+')
pat2 = re.compile('[ ]*push [0-9]+[ ]*')
pat3 = re.compile('[ ]*mov eax, (d)?word ptr \[0x[0-9a-f]+\][ ]*')
pat4 = re.compile('[ ]*mov eax, (dword ptr )?\[(?P<register>e[a-z][a-z])( )?[+-]( )?(0x)?[0-9a-f]+\][ ]*')
pat5 = re.compile('(0x[0-9a-f]+|[0-9]+)')
pat6 = re.compile('[ ]*(?P<mnemonic>(add)|(sub)) (?P<register>(esp)|(ebx)),(?P<amount>[0-9]*)[ ]*')
pat7 = re.compile('[ ]*mov eax, word ptr.*')#Match stupid size mismatch
pat8 = re.compile('[ ]*mov eax, .[xip]')#Match ridiculous register mismatch

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
    else:
      code+=_asm(line)
  return code

def oldasm(text):
  if 'mov [esp-16], eax\n  mov eax, ' in text:
    print text
    if not pat3.search(text):
      print str(pwn.asm(text)).encode('hex')
      text2 = '''
  mov [esp-16], eax
  mov eax, dword ptr [eax*4 + 0x80597bc]
'''
      print str(pwn.asm(text2)).encode('hex')
      raise Exception
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
  match = pat3.search(text)
  if match:
    print 'MATCHED %s'%match.group()
    inst = match.group()
    
    print str(pwn.asm(inst)).encode('hex')
    print str(pwn.asm('mov eax, dword ptr [0x8f]')).encode('hex')
    #print hex(int(inst[inst.find('[')+1:-1],16))
    print (  b'\xa1' + struct.pack('<I',int(inst[inst.find('[')+1:-1],16) )   ).encode('hex')
    return b'\xa1' + struct.pack('<I',int(inst[inst.find('[')+1:-1],16) ) #mov eax, dword ptr [0xcafecafe]
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
