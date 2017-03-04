
class Disassembler(object):
  ''' A disassembler takes a sequence of bytes and a base address,
      and iterates through all the instructions it disassembles.
      
      This is a generic Disassembler object.  All disassemblers
      used by this system should inherit from this parent
      object and provide implementations for all functions listed. '''
  def __init__(self,arch):
    raise NotImplementedError('Override __init__() in a child class')
  def disasm(self,bytes,base):
    raise NotImplementedError('Override disasm() in a child class')
