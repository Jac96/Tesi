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

