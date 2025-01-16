#include <sys/msg.h>
#include <sys/socket.h>
#ifndef MSG_COPY
    #define MSG_COPY        040000  /* copy (not remove) all queue messages */
#endif
typedef struct
{
        long mtype;
        char mtext[1];
}msg;
 
 
struct list_head
{
    struct list_head *next, *prev;
};
 
/* one msg_msg structure for each message */
struct msg_msg 
{
    struct list_head m_list;
    long m_type;
    size_t m_ts;        /* message text size */
    void *next;         /* struct msg_msgseg *next; */
    void *security;     /* NULL without SELinux */
    /* the actual message follows immediately */
};
