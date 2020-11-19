/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*DPDK*/

/* -------------------------------- Includes -------------------------------- */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/types.h>

#include <netinet/in.h>
#include <linux/if_ether.h>

#include <netpacket/packet.h>

#include <rte_ether.h>
#include <rte_udp.h>
#include <rte_ip.h>
#include <rte_ethdev.h>

#undef likely
#undef unlikely

/* ********************* DEFINES ********************* */

#define DEFAULT_RATE 10000000
#define DEFAULT_PKT_SIZE 64
#define DEFAULT_BST_SIZE 1

#define MAX_FRAME_SIZE 1500
#define MIN_FRAME_SIZE 64

#define SERVER_PORT 3308
#define CLIENT_PORT 3308

#define SERVER_ADDR_IP "10.0.0.1"
#define CLIENT_ADDR_IP "10.0.0.2"

#define SERVER_ADDR_MAC "02:00:00:00:00:01"
#define CLIENT_ADDR_MAC "02:00:00:00:00:02"


#define SOCK_NONE 0

#define IP_DEFAULT_TTL 64 /* from RFC 1340. */
#define IP_VERSION 0x40
#define IP_HEADER_LEN 0x05 /* default IP header length == five 32-bits words. */ // FIXME: check the$
#define IP_VERSION_HDRLEN (IP_VERSION | IP_HEADER_LEN)

#define OFFSET_ETHER (0)
#define OFFSET_IPV4 (OFFSET_ETHER + sizeof(struct rte_ether_hdr))
#define OFFSET_UDP (OFFSET_IPV4 + sizeof(struct rte_ipv4_hdr))
#define OFFSET_PAYLOAD (OFFSET_UDP + sizeof(struct rte_udp_hdr))
#define OFFSET_TIMESTAMP (OFFSET_PAYLOAD)
#define OFFSET_DATA (OFFSET_PAYLOAD)
//#define OFFSET_DATA_CS (OFFSET_PAYLOAD + sizeof(tsc_t))

#define PKT_HEADER_SIZE (OFFSET_PAYLOAD - OFFSET_ETHER)


/* ******************** STRUCTS ******************** */

#define PRINT_DPDK_ERROR(str, ...)                                             \
    fprintf(stderr, "DPDK ERROR: " str, __VA_ARGS__)

typedef unsigned int uint_t;

#define NO_ADDR_PORT                                                           \
    {                                                                          \
        .ip = {0}, .mac = { 0 }                                                \
    }

/*DPDK vio functions */

//struct config CONFIG_STRUCT_INITIALIZER = {};
//struct rte_eth_conf PORT_CONF_INIT = {};




/* ---------------------------- Type definitions ---------------------------- */

typedef char macaddr_str[18]; /* String type that can contain an Ethernet MAC address */
typedef char ipaddr_str[16]; /* String type that can contain an
                                             IPv4 address */
typedef uint64_t rate_t; /* The type of the packet sending rate */

typedef uint8_t dpdk_port_t; /* The type of the DPDK port descriptor */

typedef uint8_t byte_t; /* A type that can contain a single unsigned raw byte */

typedef unsigned int uint_t;

/* ------------------------- Common Data Structures ------------------------- */

struct sock_addr_pair {
    struct sockaddr_in ip; // NOTICE: the port number is in this structure
    struct sockaddr_ll mac;
};

struct dpdk_conf
{
    uint_t portid; // always zero
    struct rte_mempool *mbufs;
};

/* ------------------- Configuration Structure Definition ------------------- */
struct config
{
    rate_t rate;
    uint_t pkt_size;
    uint_t bst_size;

    int sock_fd;

    int local_port;
    int remote_port;

    struct sock_addr_pair local_addr;
    struct sock_addr_pair remote_addr;

    macaddr_str local_mac;
    macaddr_str remote_mac;

    ipaddr_str local_ip;
    ipaddr_str remote_ip;

    struct dpdk_conf dpdk;

};

struct config_defaults_triple {
    macaddr_str mac;
    ipaddr_str ip;
    int port_number;
};

/**
 * I dont really like this solution, but it's better than
 * nothing...
 *  */
struct config_defaults {
    struct config_defaults_triple local;
    struct config_defaults_triple remote;
};

/* ---------------------------- Public Functions ---------------------------- */

/* ******************** CONSTANTS ******************** */

extern struct stats *stats_ptr; // FIXME: why is this variable here

/* ************** FUNCTION DECLARATIONS ************** */

extern int addr_mac_set(struct sockaddr_ll *addr, const char *mac, const char *ifname);

extern int parameters_parse(int argc, char *argv[], struct config *conf);
extern void print_config(struct config *conf);

extern int dpdk_init(struct config *conf);
extern void dpdk_setup_pkt_headers(
    struct rte_ether_hdr *eth_hdr,
    struct rte_ipv4_hdr *ip_hdr,
    struct rte_udp_hdr *udp_hdr,
    struct config *conf);

extern int sock_set_sndbuff(int sock_fd, unsigned int size);
extern int sock_create(struct config *conf, uint32_t flags, bool toconnect);
extern void handle_sigint(int sig);

extern int dpdk_advertise_host_mac(struct config *conf);

extern struct config server_conf;
extern struct config client_conf;

/* **************** INLINE FUNCTIONS **************** */

#define dpdk_pkt_offset(pkt, t, offset) \
    rte_pktmbuf_mtod_offset(pkt, t, offset)

static inline bool check_checksum(byte_t *data, size_t len)
{
    if (len == 0)
        return true;

    byte_t sum = 0;

    for (size_t i = 0; i < len; ++i)
    {
        sum += data[i];
    }

    return sum == 0;
}

// Assuming that a packet will always fit into a buffer
static inline void copy_buf_to_pkt(
    void *buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{
    rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset), buf, (size_t)len);
}
