#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>  // Добавлен для htons()
#include "analizator.h"

int getsock_recv(int index) {
    int sd;
    struct sockaddr_ll s_ll;

    sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sd < 0) return -1;

    memset((void *)&s_ll, 0, sizeof(struct sockaddr_ll));
    s_ll.sll_family = PF_PACKET;
    s_ll.sll_protocol = htons(ETH_P_ALL);
    s_ll.sll_ifindex = index;

    if(bind(sd, (struct sockaddr *)&s_ll, sizeof(struct sockaddr_ll)) < 0) {
        close(sd);
        return -1;
    }

    return sd;
}
