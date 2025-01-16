#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>

void err_exit(char *s){
    perror(s);
    exit(-1);
}
void unshare_setup(void)
{
    char edit[0x100];
    int tmp_fd;

    if(unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET))
        err_exit("FAILED to create a new namespace");

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
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
}


void packet_socket_rx_ring_init(int s, unsigned int block_size,
                                unsigned int frame_size, unsigned int block_nr,
                                unsigned int sizeof_priv, unsigned int timeout) {
    int v = TPACKET_V3;
    int rv = setsockopt(s, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (rv < 0) puts("setsockopt(PACKET_VERSION)"), exit(-1);
   
    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = block_size;
    req.tp_frame_size = frame_size;
    req.tp_block_nr = block_nr;
    req.tp_frame_nr = (block_size * block_nr) / frame_size;
    req.tp_retire_blk_tov = timeout;
    req.tp_sizeof_priv = sizeof_priv;
    req.tp_feature_req_word = 0;

    rv = setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    if (rv < 0) puts("setsockopt(PACKET_RX_RING)"), exit(-1);
}

int packet_socket_setup(unsigned int block_size, unsigned int frame_size,
                        unsigned int block_nr, unsigned int sizeof_priv, int timeout) {
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) puts("socket(AF_PACKET)"), exit(-1);
    
    packet_socket_rx_ring_init(s, block_size, frame_size, block_nr, sizeof_priv, timeout);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex("lo");
    sa.sll_hatype = 0;
    sa.sll_pkttype = 0;
    sa.sll_halen = 0;

    int rv = bind(s, (struct sockaddr *)&sa, sizeof(sa));
    if (rv < 0) puts("bind(AF_PACKET)"), exit(-1);
    
    return s;
}
// count 为 pg_vec 数组的大小, 即 pg_vec 的大小为 count*8
// size/4096 为要分配的 order
int pagealloc_pad(int count, int size) {
    return packet_socket_setup(size, 2048, count, 0, 100);
}

