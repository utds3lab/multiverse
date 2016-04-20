#!/usr/bin/python
import json,sys

def search(item):
  with open('mapdump.json','rb') as f:
    mapping = json.load(f)
    if str(item) in mapping:
      return '0x%x'%int(mapping[str(item)])
    else:
      return 'not found'

def rsearch(item):
  with open('mapdump.json','rb') as f:
    mapping = json.load(f)
    for key,value in mapping.iteritems():
      if item == value:
        return '0x%x'%int(key)
    return 'not found'

if __name__ == '__main__':
  if len(sys.argv) < 2 or len(sys.argv) > 3:
    print "Correct usage: %s [-r] <address>"
  if len(sys.argv) == 2:
    print search(int(sys.argv[1],16))
  if len(sys.argv) == 3 and sys.argv[1] == '-r':
    print rsearch(int(sys.argv[2],16))
