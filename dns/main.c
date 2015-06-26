#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "dns.h"
#include "main.h"

#define RTE_LOGTYPE_NIS_DNS RTE_LOGTYPE_USER1

#define NB_SOCKETS 4

#define MAX_RX_QUEUE_PER_LCORE 4

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF   8192

#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */


#define MAX_PKT_BURST 32

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_RX_DESC_DEFAULT 128
static uint16_t nb_rxd = RTE_RX_DESC_DEFAULT;

/* mask of enabled ports */
static uint32_t nis_dns_enabled_port_mask = 0;

static unsigned int nis_dns_rx_queue_per_port = 1;

#define OUTPUT_FILE "/var/log/nis-network-monitor.log"
static FILE* output_fd;

struct mbuf_table {
	unsigned len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

static struct rte_mempool * pktmbuf_pool[NB_SOCKETS];

struct lcore_queue_conf {
	uint8_t port_id;
	uint16_t queue_id;
};

struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = 	ETH_MQ_RX_RSS, // receive side scaling, 可以把一个网卡的数据分流给多个cpu做处理， 这个模式比较适合我们的应用场景
		.split_hdr_size = 0,
		.header_split   = 0, /**< header split 是指把包头和包数据分配到不同的缓存当中, disabled 掉*/
		.hw_ip_checksum = 0, /**< IP checksum offload disabled ， 这个功能只是把ip校验和的功能交给硬件，不过由于我们这边完全没必要校验，直接忽略好了*/
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled     巨型报文的支持，一般不需要吧？ 不是很确定*/
		.hw_strip_crc   = 0, /**< CRC stripped by hardware  ， crc 校验， 不需要*/
		.hw_vlan_filter = 0, /**< VLAN 的功能没用，全部停掉好了*/
		.hw_vlan_strip = 0,
		.hw_vlan_extend = 0,
		.enable_scatter = 0  /** This makes it possible to then change mtu later, without the need of restarting a port 没用 disabled  */
	},
	.rx_adv_conf = {			/**  rss 模式决定了包如何分发给各个端口, 对我们来说，根据ip是一个比较好的选择*/
			.rss_conf = {
				.rss_key = NULL,
				.rss_hf = ETH_RSS_IP,
			},
		},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0, /* Use PMD default values */
	.tx_rs_thresh = 0, /* Use PMD default values */
	/*
	* As the example won't handle mult-segments and offload cases,
	* set the flag by default.
	*/
	.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS,
};


/* A tsc-based timer responsible for triggering statistics printout */
#define MAX_TIMER_PERIOD 300 /* 5 minute max */
static int16_t timer_period = 5 ; /* default period is 5 seconds */

static int
nis_dns_launch_one_lcore(__attribute__((unused)) void *dummy)
{
		struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
		unsigned lcore_id;
		uint8_t port_id;
		uint16_t queue_id;
		struct lcore_queue_conf *qconf;
		uint8_t i,nb_rx;
		lcore_id = rte_lcore_id();
		qconf = &lcore_queue_conf[lcore_id];
		port_id = qconf->port_id;
		queue_id = qconf->queue_id;

		if(port_id  > RTE_MAX_ETHPORTS ){
			return 0;
		}

		RTE_LOG(INFO, NIS_DNS, "dns loop on lcore  %u, port %d, queue %d \n", lcore_id, (unsigned) port_id, (unsigned)queue_id);
		struct rte_mbuf *request, *response;

		unsigned socketId = rte_lcore_to_socket_id(lcore_id);
		response = (struct rte_mbuf*) rte_pktmbuf_alloc(pktmbuf_pool[socketId]);
		prepareDNSResponse(response);

	    while(1){
			nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts_burst, MAX_PKT_BURST);
			for (i = 0; i < nb_rx; i++) {
				request = pkts_burst[i];
				rte_prefetch0(rte_pktmbuf_mtod(request, void *));
				processDNSRequest(request,response);
				rte_eth_tx_burst(port_id, queue_id, &response,1);
				rte_pktmbuf_free(request); // free buf
			}
		}
		 return 0;
}

/* display usage */
static void
nis_dns_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=icores) per port (default is 1)\n"
		   "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 5 default, 86400 maximum)\n",
	       prgname);
}

static int
nis_dns_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static unsigned int
nis_dns_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
nis_dns_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

/* Parse the argument given in the command line of the application */
static int
nis_dns_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:q:T:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			nis_dns_enabled_port_mask = nis_dns_parse_portmask(optarg);
			if (nis_dns_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				nis_dns_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			nis_dns_rx_queue_per_port = nis_dns_parse_nqueue(optarg);
			if (nis_dns_rx_queue_per_port == 0) {
				printf("invalid queue number\n");
				nis_dns_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_period = nis_dns_parse_timer_period(optarg);
			if (timer_period < 0) {
				printf("invalid timer period\n");
				nis_dns_usage(prgname);
				return -1;
			}
			break;

		/* long options */
		case 0:
			nis_dns_usage(prgname);
			return -1;

		default:
			nis_dns_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 0; /* reset getopt lib */
	return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

int
MAIN(int argc, char **argv)
{
	struct rte_eth_dev_info dev_info;
	int ret;
	uint8_t nb_ports;
	uint8_t nb_ports_available;
	uint8_t portid;
	unsigned lcore_id, rx_lcore_id;
	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = nis_dns_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid nis-dns arguments\n");

	if (rte_eal_pci_probe() < 0)
		rte_exit(EXIT_FAILURE, "Cannot probe PCI\n");

	nb_ports = rte_eth_dev_count();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	if (nb_ports > RTE_MAX_ETHPORTS)
		nb_ports = RTE_MAX_ETHPORTS;

	nb_ports_available = 0;
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((nis_dns_enabled_port_mask & (1 << portid)) == 0)
			continue;

		rte_eth_dev_info_get(portid, &dev_info);
		if(dev_info.max_rx_queues == 1){
			char pci_addr_str[16];
			snprintf(pci_addr_str, sizeof(pci_addr_str), PCI_PRI_FMT,
					dev_info.pci_dev->addr.domain, dev_info.pci_dev->addr.bus, dev_info.pci_dev->addr.devid,
					dev_info.pci_dev->addr.function);
			printf("As port %d[%s] only support one rx_queue, the -q parmater has been ignored!", portid, pci_addr_str);
			nis_dns_rx_queue_per_port = 1;
		}
		nb_ports_available++;
	}

	if (nb_ports_available == 0) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	unsigned available_icore = rte_lcore_count();
    unsigned need_icore = nb_ports_available * nis_dns_rx_queue_per_port + 1;
	if(need_icore > available_icore){
		rte_exit(EXIT_FAILURE, "No enough icores - bye\n");
	}

	output_fd = fopen(OUTPUT_FILE, "a");
	if(output_fd == NULL){
		rte_exit(EXIT_FAILURE, "Could not open out put file ! %s\n", OUTPUT_FILE);
	}

	rx_lcore_id = 0;
	for(rx_lcore_id = 0; rx_lcore_id<RTE_MAX_LCORE;rx_lcore_id++){
		lcore_queue_conf[rx_lcore_id].port_id = RTE_MAX_ETHPORTS + 1; // set to invalid port
	}

	unsigned socket = 0;
	for(socket = 0; socket < NB_SOCKETS; socket++){
		pktmbuf_pool[socket] = NULL;
	}

	// init (port, icore, queue) map
	rx_lcore_id =  -1;
	for (portid = 0; portid < nb_ports; portid++) {
		/* skip ports that are not enabled */
		if ((nis_dns_enabled_port_mask & (1 << portid)) == 0)
			continue;

		uint16_t queue_id = 0;
		uint16_t queue_count = 0;
		while(queue_count < nis_dns_rx_queue_per_port){
			rx_lcore_id = rte_get_next_lcore(rx_lcore_id, 1 , 0);
			lcore_queue_conf[rx_lcore_id].port_id  = portid;
			lcore_queue_conf[rx_lcore_id].queue_id = queue_id;
			printf("Init queue for icore , Lcore %u: RX port %u, QueueId : %u \n", rx_lcore_id,  (unsigned)portid, (unsigned)queue_id);
			queue_id++;
			queue_count++;
		}
	}

	// init ports
	for (portid = 0; portid < nb_ports; portid++) {
		if ((nis_dns_enabled_port_mask & (1 << portid)) == 0)
			continue;
		ret = rte_eth_dev_configure(portid, nis_dns_rx_queue_per_port, 1, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
						  ret, (unsigned) portid);
	}

	// init queue for every available icore
	for(rx_lcore_id = 0; rx_lcore_id<RTE_MAX_LCORE;rx_lcore_id++){
		if(lcore_queue_conf[rx_lcore_id].port_id > RTE_MAX_ETHPORTS)
			continue;
		socket = rte_lcore_to_socket_id(rx_lcore_id);

		if(pktmbuf_pool[socket]  == NULL){
			pktmbuf_pool[socket]  = rte_mempool_create("mbuf_pool", NB_MBUF,
					   MBUF_SIZE, 32,
					   sizeof(struct rte_pktmbuf_pool_private),
					   rte_pktmbuf_pool_init, NULL,
					   rte_pktmbuf_init, NULL,
					   socket, 0);
			if (pktmbuf_pool[socket] == NULL)
					rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
		}

		portid = lcore_queue_conf[rx_lcore_id].port_id;
		uint16_t queue_id =  lcore_queue_conf[rx_lcore_id].queue_id;
		ret = rte_eth_rx_queue_setup(portid, queue_id, nb_rxd,
					     rte_eth_dev_socket_id(portid), &rx_conf,
					     pktmbuf_pool[socket]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, (unsigned) portid);

		ret = rte_eth_tx_queue_setup(portid, queue_id, nb_rxd,
				rte_eth_dev_socket_id(portid), &tx_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, (unsigned) portid);
	}


	for (portid = 0; portid < nb_ports; portid++) {
		if ((nis_dns_enabled_port_mask & (1 << portid)) == 0)
			continue;
		
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, (unsigned) portid);
		rte_eth_promiscuous_enable(portid);
	}

	check_all_ports_link_status(nb_ports, nis_dns_enabled_port_mask);

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(nis_dns_launch_one_lcore, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}

