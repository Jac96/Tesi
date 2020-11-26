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
#define DEFAULT_BST_SIZE 32

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

//    size_t bytes_to_read;

    char msg[16384];
    char *msg_p;
    size_t bytes;

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


static inline void dpdk_pkt_prepare(struct rte_mbuf *pkt,
                                    struct config *conf,
                                    struct rte_ether_hdr *pkt_eth_hdr,
                                    struct rte_ipv4_hdr *pkt_ip_hdr,
                                    struct rte_udp_hdr *pkt_udp_hdr)
{

    rte_pktmbuf_reset_headroom(pkt);
    pkt->data_len = conf->pkt_size;

    pkt->pkt_len = conf->pkt_size; 

    pkt->next = NULL;

    copy_buf_to_pkt(pkt_eth_hdr,
                    sizeof(struct rte_ether_hdr),
                    pkt,
                    OFFSET_ETHER);

    copy_buf_to_pkt(pkt_ip_hdr,
                    sizeof(struct rte_ipv4_hdr),
                    pkt,
                    OFFSET_IPV4);

    copy_buf_to_pkt(pkt_udp_hdr,
                    sizeof(struct rte_udp_hdr),
                    pkt,
                    OFFSET_UDP);

    pkt->nb_segs = 1;
    pkt->ol_flags = 0;
    pkt->vlan_tci = 0;
    pkt->vlan_tci_outer = 0;
    pkt->l2_len = sizeof(struct rte_ether_hdr);
    pkt->l3_len = sizeof(struct rte_ipv4_hdr);
}

static inline uint16_t dpdk_calc_ipv4_checksum(struct rte_ipv4_hdr *ip_hdr)
{
    uint16_t *ptr16 = (unaligned_uint16_t *)ip_hdr;
    uint32_t ip_cksum;

    ptr16 = (unaligned_uint16_t *)ip_hdr;
    ip_cksum = 0;
    ip_cksum += ptr16[0];
    ip_cksum += ptr16[1];
    ip_cksum += ptr16[2];
    ip_cksum += ptr16[3];
    ip_cksum += ptr16[4];
    ip_cksum += ptr16[6];
    ip_cksum += ptr16[7];
    ip_cksum += ptr16[8];
    ip_cksum += ptr16[9];

    // Reduce 32 bit checksum to 16 bits and complement it
    ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
               (ip_cksum & 0x0000FFFF);
    if (ip_cksum > 65535)
        ip_cksum -= 65535;
    ip_cksum = (~ip_cksum) & 0x0000FFFF;
    if (ip_cksum == 0)
        ip_cksum = 0xFFFF;

    return (uint16_t)ip_cksum;
}

//DEBUG
static inline void config_print(struct config *conf) {
    printf("CONFIGURATION\n");
    printf("-------------------------------------\n");
    printf("rate (pps)\t%lu\n", conf->rate);
    printf("pkt size\t%u\n", conf->pkt_size);
    printf("bst size\t%u\n", conf->bst_size);

    printf("\n");

    printf("port local\t%d\n\n", conf->local_port);

    printf("port remote\t%d\n\n",conf->remote_port);

    printf("ip local\t%s\n\n", conf->local_ip);

    printf("ip  remote\t%s\n\n", conf->remote_ip);

    printf("mac local\t%s\n\n", conf->local_mac);

    printf("mac  remote\t%s\n\n", conf->remote_mac);

    printf("-------------------------------------\n");
}


// Setting up ETH, IP and UDP headers for later use
static inline void dpdk_setup_pkt_headers(
    struct rte_ether_hdr *eth_hdr,
    struct rte_ipv4_hdr *ip_hdr,
    struct rte_udp_hdr *udp_hdr,
    struct config *conf)
{
    uint16_t pkt_len;
    uint16_t payload_len = (uint16_t)(conf->pkt_size - (sizeof(struct rte_ether_hdr) +
                                                        sizeof(struct rte_ipv4_hdr) +
                                                        sizeof(struct rte_udp_hdr)));

    // Initialize ETH header
    rte_ether_addr_copy((struct rte_ether_addr *)conf->local_mac, &eth_hdr->s_addr);
    rte_ether_addr_copy((struct rte_ether_addr *)conf->remote_mac, &eth_hdr->d_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // Initialize UDP header
    pkt_len = (uint16_t)(payload_len + sizeof(struct rte_udp_hdr));
    udp_hdr->src_port = rte_cpu_to_be_16(conf->local_port);
    udp_hdr->dst_port = rte_cpu_to_be_16(conf->remote_port);
    udp_hdr->dgram_len = rte_cpu_to_be_16(pkt_len);
    udp_hdr->dgram_cksum = 0; /* No UDP checksum. */
 
   // Initialize IP header
    pkt_len = (uint16_t)(pkt_len + sizeof(struct rte_ipv4_hdr));
    ip_hdr->version_ihl = IP_VERSION_HDRLEN;
    ip_hdr->type_of_service = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = IP_DEFAULT_TTL;
    ip_hdr->next_proto_id = IPPROTO_UDP;
    ip_hdr->packet_id = 0;
    ip_hdr->total_length = rte_cpu_to_be_16(pkt_len);
    ip_hdr->src_addr = rte_cpu_to_be_32(conf->local_addr.ip.sin_addr.s_addr);
    ip_hdr->dst_addr = rte_cpu_to_be_32(conf->remote_addr.ip.sin_addr.s_addr);
    // Compute IP header checksum
    ip_hdr->hdr_checksum = dpdk_calc_ipv4_checksum(ip_hdr);
}

static inline size_t vio_dpdk_read(struct config *conf, void *buf, size_t size) {

    struct rte_eth_stats stats;
    const size_t data_offset = OFFSET_DATA;
    struct rte_mbuf *pkt;
    size_t pkts_rx = 0;

    while(pkts_rx == 0){
      pkts_rx = rte_eth_rx_burst(conf->dpdk.portid, 0, &pkt, 1);
    }

    rte_eth_stats_get(conf->dpdk.portid, &stats);
    conf->bytes = stats.ibytes - data_offset;
    rte_eth_stats_reset(conf->dpdk.portid);
    rte_memcpy(buf, rte_pktmbuf_mtod_offset(pkt, char *, data_offset), conf->bytes);

    rte_pktmbuf_free(pkt);

    return size;
}

static inline size_t vio_dpdk_write(struct config *conf, const void *buf, size_t size) {

    const size_t data_offset = OFFSET_DATA;
    struct rte_ether_hdr pkt_eth_hdr;
    struct rte_ipv4_hdr pkt_ip_hdr;
    struct rte_udp_hdr pkt_udp_hdr;
    struct rte_mbuf* pkt;

    conf->pkt_size = data_offset + size;
    dpdk_setup_pkt_headers(&pkt_eth_hdr, &pkt_ip_hdr, &pkt_udp_hdr, conf);
    pkt = rte_mbuf_raw_alloc(conf->dpdk.mbufs);

    if (unlikely(pkt == NULL))
    {
        fprintf(
            stderr,
            "WARN: Could not allocate a buffer, using less packets than required burst size!\n");
    }

    dpdk_pkt_prepare(pkt, conf, &pkt_eth_hdr, &pkt_ip_hdr, &pkt_udp_hdr);
    rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char*, data_offset), buf, size);
    rte_eth_tx_burst(conf->dpdk.portid, 0, &pkt, 1);
    rte_pktmbuf_free(pkt);

    return size;
}

static inline int dpdk_init(struct config *conf) {

    int res;

    struct rte_eth_conf PORT_CONF_INIT = {};
//    config_print(conf);

    uint_t ports;   /* Number of ports available, must be equal to 1 for this
                       application if DPDK is used. */
    uint_t n_mbufs; /* Number of mbufs to create in a pool. */
    uint_t port_id; /* The id of the DPDK port to be used. */

    uint16_t tx_ring_descriptors, rx_ring_descriptors;

    tx_ring_descriptors = 2048;
    rx_ring_descriptors = 2048;

    /* Get the number of DPDK ports available */
    ports = rte_eth_dev_count_avail();
    printf("PORTS: %d\n", ports);

    if (ports == 0) {
        PRINT_DPDK_ERROR("No ports found, %d == 0.\n", ports);
        return -1;
    }

    /* Get the number of desired buffers and descriptors */
    n_mbufs = RTE_MAX((rx_ring_descriptors + tx_ring_descriptors + conf->bst_size + 512), 8192U * 2);

    /* Set it to an even number (easier to determine cache size) */
    if (n_mbufs & 0x01)
        ++n_mbufs;


    // FINDING THE BIGGEST DIVISOR UNDER CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE
    uint_t s_divisor = 1;
    uint_t b_divisor = n_mbufs;
    do
    {
        do
        {
            ++s_divisor;
            // Iterate over odds number only after checking 2
        } while ((n_mbufs % s_divisor != 0) && (!(s_divisor & 0x1) || s_divisor == 2));

        b_divisor = n_mbufs / s_divisor;
    } while (b_divisor > 512); // CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE=512 in DPDK configuration file
    uint_t cache_size = b_divisor;

    conf->dpdk.mbufs = rte_pktmbuf_pool_create(
        "mbuf_pool",
        n_mbufs,
        cache_size,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());

    if (conf->dpdk.mbufs == NULL)
    {
        PRINT_DPDK_ERROR("Unable to allocate mbufs: %s.\n", rte_strerror(rte_errno));
        return -1;
    }

    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf local_port_conf = PORT_CONF_INIT;
    struct rte_eth_dev_info dev_info;

    local_port_conf.rxmode.split_hdr_size = 0;
    local_port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;

    /* Since we checked that there must be only one port, its port id is 0. */
    port_id = 0;
    conf->dpdk.portid = port_id;
    rte_eth_dev_info_get(port_id, &dev_info);

    /* If able to offload TX to device, do it */
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
       local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    /* Configure device */
    res = rte_eth_dev_configure(port_id, 1, 1, &local_port_conf);
    if (res < 0) {
        PRINT_DPDK_ERROR("Cannot configure device: %s.\n",
                         rte_strerror(rte_errno));
        return -1;
    }

    /* Adjust number of TX and RX descriptors */
    res = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &rx_ring_descriptors,
                                           &tx_ring_descriptors);

    if (res < 0) {
        PRINT_DPDK_ERROR("Cannot adjust number of descriptors: %s.\n",
                         rte_strerror(rte_errno));
        return -1;
    }

    /* Get the source mac address that is associated with the given port */
    // FIXME: NOT USED, USER MUST CONFIGURE THE MAC ADDRESS MANUALLY FROM
    // COMMAND LINE
    //rte_eth_macaddr_get(port_id, &conf->dpdk.src_mac_addr);

    /* Configure TX queue */
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = local_port_conf.txmode.offloads;
    res = rte_eth_tx_queue_setup(port_id, 0, tx_ring_descriptors,
                                 rte_eth_dev_socket_id(port_id), &txq_conf);

    if (res < 0) {
        PRINT_DPDK_ERROR("Cannot configure TX: %s.\n", rte_strerror(rte_errno));
        return -1;
    }

    /* Configure RX queue */
    res = rte_eth_rx_queue_setup(port_id, 0, rx_ring_descriptors,
                                 rte_eth_dev_socket_id(port_id), NULL,
                                 conf->dpdk.mbufs);

    if (res < 0) {
        PRINT_DPDK_ERROR("Cannot configure RX: %s.\n", rte_strerror(rte_errno));
        return -1;
    }

    /* Bring the device up */
    res = rte_eth_dev_start(port_id);
    if (res < 0) {
        PRINT_DPDK_ERROR("Cannot start device: %s.\n", rte_strerror(rte_errno));
        return -1;
    }

    /* Enable promiscuous mode */
    /* NOTICE: The device will show packets that are not meant for the
     * device MAC address too.
     * */
    res = rte_eth_promiscuous_enable(port_id);

    if(res == 0)
        printf("OK!\n");

    return 0;
}


