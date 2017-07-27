#!/bin/bash
# Match the offset (index 1) and size (index 2) of the .text section so we can create a file
# containing only the raw bytes of the .text section.
re='.text[[:space:]]+PROGBITS[[:space:]]+[0-9a-f]+[[:space:]]+([0-9a-f]+)[[:space:]]+([0-9a-f]+)'
textsection=$(readelf -S -W x86_populate_gm | grep '.text') 
echo "yo $textsection"
if [[ ${textsection} =~ ${re} ]]; then 
	dd if=x86_populate_gm of=x86_popgm skip=$((0x${BASH_REMATCH[1]})) bs=1 count=$((0x${BASH_REMATCH[2]})) 
fi 
textsection=$(readelf -S -W x64_populate_gm | grep '.text')
if [[ ${textsection} =~ ${re} ]]; then
	dd if=x64_populate_gm of=x64_popgm skip=$((0x${BASH_REMATCH[1]})) bs=1 count=$((0x${BASH_REMATCH[2]})) 
fi
