# curiocunngios (Alex)

## easypwn 20 mins


## harderpwn 30 - 40 mins
- tasks
    - leak canary to bypass stack canary protection
    - use rop chain to pop a shell since there's no win function
    - use the shell to "cat flag.txt"

- ROP
    - chaining instructions, or functions placed on the stack by keep returning to instructions or functions ending with ret "ret" (pop rip), which pops addresses placed on the current stack frame to rip to continue execution

- ### leaking libc addresses
    - the goal here is to call `puts(<address that contains libc>)`
    - rop chain structure be like:
    - `pop rdi ; ret`
    - address that contains a libc address (automate with pwntools functions or find dynamically using gdb)
    - put address of `puts@plt` on the rop chain so that the previos `ret` pops the address of puts to rip (program counter)
    - put address of UwU_main at the end of the ROP chain, so that the `ret` of `puts()` function "ret" to UwU_main, go back to UwU_main again so that we input a new ROP chain that calls `system("/bin/sh")`

- ### ROP chain for system("/bin/sh")
    - pop rdi ; ret
    - address of /bin/sh
    - system(), a libc library function written by other programmers
        - maybe a wrapper for execve() (syscall 59) 

