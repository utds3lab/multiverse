#!/usr/bin/python
import sys,os
import subprocess
import shutil

import renabler

def extract_libraries(fname):
  result = subprocess.check_output('ldd %s'%sys.argv[1], shell=True)
  libs = result.split('\n')
  paths = []
  for lib in libs:
    if '=>' in lib:
      path = lib[lib.find('=>')+2:lib.find(' (0x')].strip()
      if path != '':
        paths.append(path)
  return paths

def rewrite_libraries(libpath,paths):
  renabler.write_so = True
  for path in paths:
    (base,fname) = os.path.split(path)
    libname = os.path.join(libpath,fname)
    shutil.copy(path,libname)
    renabler.renable(libname)
    os.remove(libname)
    shutil.move(libname+'-r',libname)
    shutil.move(libname+'-r-map.json',libname+'-map.json')
    shutil.move(libname+'-r-stat.json',libname+'-stat.json')

if __name__ == '__main__':
  if len(sys.argv) == 2:
    print 'Getting required libraries for %s'%sys.argv[1]
    paths = extract_libraries(sys.argv[1])

    print 'Rewriting libraries'
    (base,fname) = os.path.split(sys.argv[1])
    libpath = os.path.join(base,fname+'-libs-r')
    if not os.path.exists(libpath):
      os.makedirs(libpath)
    rewrite_libraries(libpath,paths)

    print 'Rewriting main binary'
    renabler.write_so = False
    renabler.renable(sys.argv[1])
  else:
    print "Error: must pass executable filename.\nCorrect usage: %s <filename>"%sys.argv[0]
