
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/*DPDK vio functions*/


#include "vio_priv.h"

#include <stdint.h>
#include <numa.h>

#include <stdlib.h>
#include "my_dbug.h"

#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_udp.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include <rte_errno.h>

#include <string.h>

#include <fcntl.h>
#include <linux/if_ether.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>


/**
 * Initialize configuration with the given default parameters.
 *
 * NOTICE: this will revert a configuration to default parameters even in the
 * case in which no defaults are supplied (NULL).
 *
 * \param conf the configuration to be initialized.
 * \param defaults values to be used to fill mac address, ip address and port
 * numbers, if provided. Can be NULL.
 *
 * */

struct rte_eth_conf PORT_CONF_INIT = {};

/**
 * Construct a MAC address from the given string.
 *
 * \return 0 on success, -1 otherwise.
 * */
int addr_mac_set(struct sockaddr_ll *addr, const char *str,
                               const char *ifname) {
    memset(addr, 0, sizeof(struct sockaddr_ll));
    addr->sll_family = AF_PACKET;
    addr->sll_protocol = htons(ETH_P_ALL);
    addr->sll_ifindex = (ifname == NULL) ? 0 : if_nametoindex(ifname);
    addr->sll_halen = sizeof(
        addr->sll_addr); // TODO: check if it's right, otherwise just put 6 here

    int res;

    res = sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", addr->sll_addr + 0,
                 addr->sll_addr + 1, addr->sll_addr + 2, addr->sll_addr + 3,
                 addr->sll_addr + 4, addr->sll_addr + 5);

    if (res != 6) {
        memset(addr, 0, 6);
        return -1;
    }

    return 0;
}

/**
 * Construct an IPv4 address from the given string.
 *
 * \return 0 on success, an error code otherwise.
 * */
static int addr_ip_set(struct sockaddr_in *addr, const char *str) {
    int res;

    addr->sin_family = AF_INET;
    res = inet_aton(str, &addr->sin_addr);
    if (res == 0) {
        return -1;
    }

    return 0;
}

/**
 * Set the port number of the given address.
 * */
static void addr_port_number_set(struct sockaddr_in *addr, int port) {
    addr->sin_port = htons(port);
}

#define dpdk_pkt_offset(pkt, t, offset) \
    rte_pktmbuf_mtod_offset(pkt, t, offset)

static inline void produce_data(const void *payload_v, const uchar *buf, size_t size) {

    //const uchar *payload = (const uchar *)payload_v;
    memcpy((void *)buf, payload_v, size);

}

static inline void dpdk_produce_data_offset(struct rte_mbuf *pkt, ssize_t offset, const uchar* buf, size_t size)
{
    produce_data(dpdk_pkt_offset(pkt, rte_mbuf*, offset), buf, size);
}

static inline void consume_data(const void *payload_v, uchar *buf, size_t size)
{
    /*bool checksum_valid = check_checksum(data, len);

    if (!checksum_valid)
    {
        fprintf(stderr, "ERROR: received message checksum is not correct!\n");
    }*/

    //uchar* payload = (uchar *)payload_v;
    memcpy((void *)buf, payload_v, size);    
}

static inline void dpdk_consume_data_offset(struct rte_mbuf *pkt, ssize_t offset, uchar* buf, size_t size)
{
    consume_data(dpdk_pkt_offset(pkt, rte_mbuf*, offset), buf, size);
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
void config_print(struct config *conf) {
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

    //printf("conf->dpdk.mbuf: %s\n", conf->dpdk.mbuf);

    printf("-------------------------------------\n");
}


// Setting up ETH, IP and UDP headers for later use
void dpdk_setup_pkt_headers(
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

/**
 * Get the appropriate amount of cache size for the given number of buffers.
 *
 * The cache size must be:
 * \li a divisor of the number of buffers;
 * \li smaller than CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE.
 *
 * \param n_mbufs is the number of buffers.
 *
 * \return the size of the cache.
 * */
int get_cache_size(uint_t n_mbufs) {
    /*
     * Idea behind this loop: the biggest divisor is equal to N / the smallest
     * divisor. However, the biggest divisor may be very big, so we keep
     * iterating until we find the biggest divisor that is also smaller than
     * CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE.
     * */
    uint_t s_divisor = 1;
    uint_t b_divisor = n_mbufs;
    do {
        do {
            ++s_divisor;
            /* Iterate over odds number only after checking 2 */
        } while ((n_mbufs % s_divisor != 0) &&
                 (!(s_divisor & 0x1) || s_divisor == 2));

        b_divisor = n_mbufs / s_divisor;
    } while (b_divisor > 512);
    /* CONFIG_RTE_MEMPOOL_CACHE_MAX_SIZE=512 [from DPDK configuration file] */

    return b_divisor;
}

/* ---------------------------- Public Functions ---------------------------- */

/**
 * Initialize DPDK environment with the appropriate parameters.
 *
 * This function should be invoked AFTER invoking the
 * config_parse_application_parameters function.
 *
 * This means that it will operate on the parameters of the application starting
 * from the one equal to "--".
 *
 * \return 0 on success, an error code otherwise.
 * */
int dpdk_init(struct config *conf) {

    DBUG_TRACE;

    int res;

    config_print(conf);

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
    n_mbufs = RTE_MAX(
        (rx_ring_descriptors + tx_ring_descriptors + conf->bst_size + 512),
        8192U * 2);

    /* Set it to an even number (easier to determine cache size) */
    if (n_mbufs & 0x01)
        ++n_mbufs;

    /* Create the appropriate pool of buffers in hugepages memory. */
    conf->dpdk.mbufs =
       rte_pktmbuf_pool_create("mbuf_pool", n_mbufs, get_cache_size(n_mbufs),
                                0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
                        

    if (conf->dpdk.mbufs == NULL) {
        PRINT_DPDK_ERROR("Unable to allocate mbufs: %s.\n",
                         rte_strerror(rte_errno));
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

    struct rte_ether_addr addr;
    res = rte_eth_macaddr_get(port_id, &addr);
    if (res != 0)
      return res;

    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
        port_id,
        addr.addr_bytes[0], addr.addr_bytes[1],
        addr.addr_bytes[2], addr.addr_bytes[3],
        addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Enable promiscuous mode */
    /* NOTICE: The device will show packets that are not meant for the
     * device MAC address too.
     * */
    res = rte_eth_promiscuous_enable(port_id);

    if(res == 0)
        printf("OK!\n");

    //printf("Prova: %s\n", conf->prova);

    return 0;
}

size_t vio_dpdk_read(Vio *vio, uchar *buf, size_t size) {

    DBUG_TRACE;

    int res;

    const size_t data_offset = OFFSET_DATA_SR;

    struct rte_eth_stats	stats;

    //struct rte_ether_hdr pkt_eth_hdr;
    //struct rte_ipv4_hdr pkt_ip_hdr;
    //struct rte_udp_hdr pkt_udp_hdr;

    struct rte_mbuf *pkts_burst[1];

    size_t pkts_rx = 0;
    //size_t i;

    //dpdk_setup_pkt_headers(&pkt_eth_hdr, &pkt_ip_hdr, &pkt_udp_hdr, &vio->dpdk_config);


    while(pkts_rx == 0){
      pkts_rx = rte_eth_rx_burst(vio->dpdk_config.dpdk.portid, 0, pkts_burst, 8);

      printf("PACCHETTI RICEVUTI: %lu\n\n", pkts_rx);

      res = rte_eth_stats_get(vio->dpdk_config.dpdk.portid, &stats);

      if (res == 0) printf("OK stats\n");

      printf("ipackets: %lu\n", stats.ipackets);
      printf("opackets: %lu\n", stats.opackets);
      printf("ibytes: %lu\n", stats.ibytes);
      printf("obytes: %lu\n", stats.obytes);
      printf("imissed: %lu\n", stats.imissed);
      printf("ierrors: %lu\n", stats.ierrors);
      printf("oerrors: %lu\n", stats.oerrors);
      printf("rx_nombuf: %lu\n\n\n", stats.rx_nombuf);

    }

    dpdk_consume_data_offset(pkts_burst[0], data_offset, buf, size);

    printf("PKTS_RX: %lu %lu\n\n", pkts_rx, size);

    rte_pktmbuf_free(pkts_burst[0]);

    return size;
}

size_t vio_dpdk_write(Vio *vio, const uchar *buf, size_t size) {

    DBUG_TRACE;

    struct rte_eth_stats	stats;

    int res = 0;

    const size_t data_offset = OFFSET_DATA_SR;

    struct rte_ether_hdr pkt_eth_hdr;
    struct rte_ipv4_hdr pkt_ip_hdr;
    struct rte_udp_hdr pkt_udp_hdr;

    struct rte_mbuf *pkts_burst[DEFAULT_BST_SIZE];
    struct rte_mbuf *pkt;

    size_t pkts_tx;

    vio->dpdk_config.pkt_size = size + sizeof(struct rte_ether_hdr) + 
		sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);

    dpdk_setup_pkt_headers(&pkt_eth_hdr, &pkt_ip_hdr, &pkt_udp_hdr, &vio->dpdk_config);

    pkt = rte_mbuf_raw_alloc(vio->dpdk_config.dpdk.mbufs);

    if (unlikely(pkt == NULL))
    {
        fprintf(
            stderr,
            "WARN: Could not allocate a buffer, using less packets than required burst size!\n");
    }

    dpdk_pkt_prepare(pkt, &vio->dpdk_config, &pkt_eth_hdr, &pkt_ip_hdr, &pkt_udp_hdr);
    dpdk_produce_data_offset(pkt, data_offset, buf, size);

    //pkt = (rte_mbuf*)buf;

    pkts_burst[0] = pkt;

    pkts_tx = rte_eth_tx_burst(vio->dpdk_config.dpdk.portid, 0, pkts_burst, 1);
    printf("\nPACKET SENT: %lu\n", pkts_tx);

    res = rte_eth_stats_get(vio->dpdk_config.dpdk.portid, &stats);

    if (res == 0) printf("OK stats\n");

    printf("ipackets: %lu\n", stats.ipackets);
    printf("opackets: %lu\n", stats.opackets);
    printf("ibytes: %lu\n", stats.ibytes);
    printf("obytes: %lu\n", stats.obytes);
    printf("imissed: %lu\n", stats.imissed);
    printf("ierrors: %lu\n", stats.ierrors);
    printf("oerrors: %lu\n", stats.oerrors);
    printf("rx_nombuf: %lu\n\n\n", stats.rx_nombuf);

    //config_print(&vio->dpdk_config);


    rte_pktmbuf_free(pkts_burst[0]);

    return 1 * size;
}
