# 5/6/2026 agenda

## easypwn 20 mins
- buffer overflow and modify return address to win function

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



# 12/6/2026 agenda (brief)
- the goal today is to understand the most basic UAF (Use-After-Free) vulnerability
- will go through 3 examples
    - two of them are kernel, which involves advanced exploitation techniques. 
    - But the heap bug relate to the exact same concept, will focus and walk through that.


## Example 1 (freebie-hard from pwn.college yellow belt heap challenge)
- target: learn the basic UAF concept and get the flag


## Exapmle 2 (UIUCTF babykernel)
- Relatively easy kernel exploitation challenge
- will walk through vulnerability analysis (heap bug) and brief attack flow
- will not walk through detailed exploitation demonstration
- can read solve script and analyse it yourself
    - or ask me to vide record a demonstration to walk through each throught process

## If time allows: Example 3 IPS (old kernel pwn challenge)
- will walk through vulnerability analysis (heap bug)
- will not walk through detailed exploitation demonstration