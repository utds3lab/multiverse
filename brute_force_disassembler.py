import capstone
from disassembler import Disassembler

class BruteForceDisassembler(Disassembler):
  ''' Brute-force disassembler that disassembles bytes
      from every offset; all possible code that could 
      execute is disassembled.  Overlapping instructions are
      flattened out and duplicate sequences are connected
      with jump instructions.

      Uses Capstone as its underlying linear disassembler.'''

  def __init__(self,arch):
    if arch == 'x86':
      self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    elif arch == 'x86-64':
      self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
      raise NotImplementedError( 'Architecture %s is not supported'%arch )
    self.md.detail = True

  def disasm(self,bytes,base):
    print 'Starting disassembly...'
    dummymap = {}
    ten_percent = len(bytes)/10
    for instoff in range(0,len(bytes)):
      if instoff%ten_percent == 0:
        print 'Disassembly %d%% complete...'%((instoff/ten_percent)*10)
      while instoff < len(bytes):
        off = base+instoff
        try:
          if not off in dummymap: #If this offset has not been disassembled
            insts = self.md.disasm(bytes[instoff:instoff+15],base+instoff)#longest x86/x64 instr is 15 bytes
            ins = insts.next() #May raise StopIteration
            instoff+=len(ins.bytes)
            dummymap[ins.address] = True # Show that we have disassembled this address
            yield ins
          else: #If this offset has already been disassembled
            yield None #Indicates we encountered this offset before
            break #Stop disassembling from this starting offset
        except StopIteration: #Not a valid instruction
          break #Stop disassembling from this starting offset
    raise StopIteration

