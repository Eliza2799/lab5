#ifndef ANALIZATOR_H
#define ANALIZATOR_H

#include <linux/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>

#define PROMISC_MODE_ON 1
#define PROMISC_MODE_OFF 0

struct ifparam {
    __u32 ip;
    __u32 mask;
    int mtu;
    int index;
};

extern struct ifparam ifp;

int getifconf(__u8 *intf, struct ifparam *ifp, int mode);
int getsock_recv(int index);

#endif
