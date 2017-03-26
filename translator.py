
class Translator(object):
  ''' A Translator converts the original instructions from a source
      binary into their corresponding translated instructions for
      the rewritten binary.  This includes translating addresses
      for jmp/JCC/call/ret destinations and inserting user-defined
      instrumentation code around instructions. 

      This is a generic Translator object.  All translators
      used by this system should inherit from this parent
      object and provide implementations for all functions listed.'''
  def __init__(self,before_callback,context):
    raise NotImplementedError('Override __init__() in a child class')
  def translate_one(self,ins,mapping):
    raise NotImplementedError('Override translate_one() in a child class')
  def translate_uncond(self,ins,mapping):
    raise NotImplementedError('Override translate_uncond() in a child class')
  def translate_cond(self,ins,mapping):
    raise NotImplementedError('Override translate_cond() in a child class')
  def translate_ret(self,ins,mapping):
    raise NotImplementedError('Override translate_ret() in a child class')
  def remap_target(self,addr,mapping,target,offs):
    raise NotImplementedError('Override remap_target() in a child class')
