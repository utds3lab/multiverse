
class Context(object):

  def __init__(self):
    self.plt = {}
    self.oldbase = 0x0
    self.newbase = 0x09000000
    self.lookup_function_offset = 0x8f
    self.secondary_lookup_function_offset = 0x8f #ONLY used when rewriting ONLY main executable
    self.mapping_offset = 0x8f
    self.global_sysinfo = 0x8f	#Address containing sysinfo's address
    self.global_flag = 0x8f
    self.global_lookup = 0x7000000	#Address containing global lookup function
    self.popgm = 'popgm'
    self.popgm_offset = 0x8f
    self.new_entry_off = 0x8f
    self.write_so = False
    self.exec_only = False
    self.no_pic = False
    self.get_pc_thunk = None
    self.num_new_segments = 4 # 4 new segments in the main binary
    self.move_phdrs_to_text = False # Do not relocate phdrs to text section by default
    self.stat = {}
    self.stat['indcall'] = 0
    self.stat['indjmp'] = 0
    self.stat['dircall'] = 0
    self.stat['dirjmp'] = 0
    self.stat['jcc'] = 0
    self.stat['ret'] = 0
    self.stat['origtext'] = 0
    self.stat['newtext'] = 0
    self.stat['origfile'] = 0
    self.stat['newfile'] = 0
    self.stat['mapsize'] = 0
    self.stat['lookupsize'] = 0
    #List of library functions that have callback args; each function in the dict has a list of
    #the arguments passed to it that are a callback (measured as the index of which argument it is)
    self.callbacks = {'__libc_start_main':[0,3,4]}
