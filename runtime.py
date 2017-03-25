
class Runtime(object):
  ''' The BinForce runtime library includes all code needed to run
      the rewritten binary.  This includes the functions to populate
      the global mapping and perform lookups in mappings.

      This is a generic Runtime object.  All runtimes
      used by this system should inherit from this parent
      object and provide implementations for all functions listed.'''
  def __init__(self,context):
    raise NotImplementedError('Override __init__() in a child class')
  def get_lookup_code(self,base,size,lookup_off,mapping_off):
    raise NotImplementedError('Override get_lookup_code() in a child class')
  def get_secondary_lookup_code(self,base,size,sec_lookup_off,mapping_off):
    raise NotImplementedError('Override get_secondary_lookup_code() in a child class')
  def get_global_lookup_code(self):
    raise NotImplementedError('Override get_global_lookup_code() in a child class')
  def get_auxvec_code(self,entry):
    raise NotImplementedError('Override get_auxvec_code() in a child class')
  def get_popgm_code(self):
    raise NotImplementedError('Override get_popgm_code() in a child class')
