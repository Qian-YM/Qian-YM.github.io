#include <sched.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#define PACKET_VERSION 10
#define PACKET_TX_RING 13

int cmd[2];
int request[2];
int dev_fd;

enum{
    ALLOC,
    FREE,
    EXIT

};

int alloc_page(){
    struct tpacket_req req;
    int socket_fd = socket(PF_PACKET, SOCK_RAW, PF_PACKET);
    if(socket_fd < 0) {
        perror("socket");
        exit(-1);
    }
    int version = TPACKET_V1;
    int ret = setsockopt(socket_fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    if(ret < 0) {
        perror("setsockopt");
        exit(-1);
    }
    memset(&req, 0, sizeof(req));
    req.tp_block_size = 0x1000;
    req.tp_block_nr = 1;
    req.tp_frame_size = 0x1000;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;
    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req));
    if(ret < 0) goto opt_error;
    puts("alloc successful!");

    return socket_fd;
create_error:
    puts("create socket error!");
    return -1;
opt_error:
    puts("opt error!");
    return -1;

}

void free_page(int fd){
    close(fd);

}
int alloc_cmd(int index){
    int order = ALLOC;
    write(cmd[1], &order, 4);
    int idx = index;
    write(cmd[1], &idx, 4);
    int res = -1;
    read(request[0], &res, 4);
    printf("alloc socket_fd == %d\n", res);
    return res;

}
void free_cmd(int index){
    int order = FREE;
    write(cmd[1], &order, 4);
    int idx = index;
    write(cmd[1], &idx, 4);
    printf("free_page!\n");
    return ;

}
void handler(){
    unshare(CLONE_NEWUSER | CLONE_NEWNET);
    int socket_fds[0x2000];
    int order;
    char content[0x200];
    int index;
    while(1){
        read(cmd[0], &order, 4);
        switch(order){
            case ALLOC:
                 read(cmd[0], &index, 4);
                 socket_fds[index] = alloc_page();
                 write(request[1], &socket_fds[index], 4);
                 break;
            case FREE:
                 read(cmd[0], &index, 4);
                 free_page(index);
                 break;
                   

            case EXIT:
                    exit(0);
                    break;
            default:
                    puts("error order!");

        }

    }


}

void exit_cmd(){
    int order = EXIT;
    write(cmd[1], &order, 4);


}
void page_init(){
    pipe(cmd);
    pipe(request);
    if(!fork()){
        handler();
    }
}
