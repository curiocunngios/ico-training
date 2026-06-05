# curiocunngios (Alex)

## easypwn 20 mins


## harderpwn 30 - 40 mins
- leak canary
- pop a shell


- chaining instructions, or functions placed on the stack by keep doing "ret" (pop rip)

- 

- want to leak libc addresses
    - pop rdi
    - address that contains a libc address
    - puts() ; @plt GOT

- pop rdi ; ret
- address of /bin/sh
- system(), a libc library function written by other programmers
    - maybe a wrapper for execve() (syscall 59) 

