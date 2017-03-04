
class Mapper(object):
  ''' A mapper maps old addresses to new addresses and old
      instructions to new instructions.

      This is a generic Mapper object.  All mappers
      used by this system should inherit from this parent
      object and provide implementations for all functions listed.'''
  
  def __init__(self,arch,bytes,base,entry):
    raise NotImplementedError('Override __init__() in a child class')
  def gen_mapping(self):
    raise NotImplementedError('Override gen_mapping() in a child class')
  def gen_newcode(self):
    raise NotImplementedError('Override gen_newcode() in a child class')
