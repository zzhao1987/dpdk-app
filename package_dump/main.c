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
#include <rte_udp.h>
#include "main.h"

#define RTE_LOGTYPE_NIS_DUMP RTE_LOGTYPE_USER1

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


static uint32_t nis_package_dump_enabled_port_mask = 0;
static int32_t output_package_number = 1000;
static uint8_t dump_port = 0;

#define OUTPUT_FILE "/var/tmp/package_dump.pacp"
static FILE* output_fd;

#pragma pack(push) //保存对齐状态
#pragma pack(1)    // 因为以下2个结构体都是要直接往文件里面写的,所以要排除字节对其

struct pcap_file_header{
    uint32_t    magic;
    uint16_t    version_major;
    uint16_t    version_minor;
    int32_t     thiszone;
    uint32_t    sigfigs;
    uint32_t    snaplen;
    uint32_t    linktype;
};

struct pacp_pkthdr{
    uint32_t    tv_sec;             // 秒
    uint32_t    tv_usec;            // 微秒
    uint32_t    caplen;             // 保存下来的数据包长度
    uint32_t    len;                // 数据包的真是长度, 不一定要保留所有数据包数据
};
#pragma pack(pop)//恢复对齐状态

static struct pcap_file_header common_file_header = { // 通用的文件头
        .magic = 0xA1B2C3D4,
        .version_major = 0x02,
        .version_minor = 0x04,
        .thiszone  =    0,
        .sigfigs   =    0,
        .snaplen    =   0xff,  // 抓包数据最大长度, 最小是60(tcp最大头)
        .linktype   =   1,    // 链路类型, 1代表ethernet
};


static struct rte_mempool *pktmbuf_pool;

static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode =     ETH_MQ_RX_RSS, // receive side scaling, 可以把一个网卡的数据分流给多个cpu做处理， 这个模式比较适合我们的应用场景
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
    .rx_adv_conf = {            /**  rss 模式决定了包如何分发给各个端口, 对我们来说，根据ip是一个比较好的选择*/
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

static int nis_package_dump_output_package(struct rte_mbuf *package)
{
    struct pacp_pkthdr hdr;
    struct rte_pktmbuf* package_hdr = &package->pkt;
    struct ether_hdr *eth_hdr;
    eth_hdr = rte_pktmbuf_mtod(package, struct ether_hdr *);
    if (unlikely(eth_hdr->ether_type != 8)){
        return 0;
    }

    time_t time_tmp;
    time(&time_tmp);

    hdr.tv_sec = time_tmp;
    hdr.tv_usec = 0;
    hdr.len = package_hdr->data_len;
    hdr.caplen = common_file_header.snaplen;
    if(hdr.caplen > hdr.len){
        hdr.caplen = hdr.len;
    }

    // output packet header
    fwrite(&hdr, sizeof(struct pacp_pkthdr), 1, output_fd);
    // output packet data
    fwrite(package_hdr->data, hdr.caplen, 1, output_fd);
    fflush(output_fd);
    return 1;
}


static int
nis_package_dump_launch_one_lcore(__attribute__((unused)) void *dummy)
{
        struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
        uint8_t i,nb_rx;
        int32_t count;
        RTE_LOG(INFO, NIS_DUMP, "dump start \n");
        struct rte_mbuf *package;

        // 输出pacp文件头
        fwrite(&common_file_header, sizeof(struct pcap_file_header), 1, output_fd);

        count = 0;
        while(count < output_package_number){
            nb_rx = rte_eth_rx_burst(dump_port, 0, pkts_burst, MAX_PKT_BURST);
            for (i = 0; i < nb_rx; i++) {
                if (unlikely( count >= output_package_number)){
                    break;
                }
                package = pkts_burst[i];
                rte_prefetch0(rte_pktmbuf_mtod(package, void *));
                if(likely(nis_package_dump_output_package(package) == 1)){
                    count++;
                }
                rte_pktmbuf_free(package); // free buf
            }
        }
        fclose(output_fd);
        return 0;
}

/* display usage */
static void
nis_package_dump_usage(const char *prgname)
{
    printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
           "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
           "  -l dump package count limit \n"
           "  -s snap_len \n",
           prgname);
}

static int
nis_package_dump_parse_portmask(const char *portmask)
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

static int
nis_package_dump_parse_package_number(const char *q_arg)
{
    char *end = NULL;
    int n;

    /* parse number string */
    n = strtol(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;
    if (n >= 100000)
        return -1;

    return n;
}


static int
nis_package_dump_parse_package_len(const char *q_arg)
{
    char *end = NULL;
    int n;

    /* parse number string */
    n = strtol(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return 0;
    if (n < 0)
        return 0;

    return n;
}

/* Parse the argument given in the command line of the application */
static int
nis_package_dump_parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        {NULL, 0, 0, 0}
    };

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "p:s:l:",
                  lgopts, &option_index)) != EOF) {

        switch (opt) {
        /* portmask */
        case 'p':
            nis_package_dump_enabled_port_mask = nis_package_dump_parse_portmask(optarg);
            if (nis_package_dump_enabled_port_mask == 0) {
                printf("invalid portmask\n");
                nis_package_dump_usage(prgname);
                return -1;
            }
            break;

        /* package number */
        case 'l':
            output_package_number = nis_package_dump_parse_package_number(optarg);
            if (output_package_number < 0) {
                printf("invalid package number, should in 0 ~ 100000 \n");
                nis_package_dump_usage(prgname);
                return -1;
            }
            break;

            /* package number */
        case 's':
            common_file_header.snaplen = nis_package_dump_parse_package_len(optarg);
            if (common_file_header.snaplen < 60 || common_file_header.snaplen > 1000) {
                printf("invalid capture package len, should in 60 ~ 1000 \n");
                nis_package_dump_usage(prgname);
                return -1;
            }
            break;

        /* long options */
        case 0:
            nis_package_dump_usage(prgname);
            return -1;

        default:
            nis_package_dump_usage(prgname);
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
    int ret;
    uint8_t nb_ports;
    uint8_t nb_ports_available;
    uint8_t portid;
    unsigned lcore_id;
    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    /* parse application arguments (after the EAL ones) */
    ret = nis_package_dump_parse_args(argc, argv);
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
        if ((nis_package_dump_enabled_port_mask & (1 << portid)) == 0)
            continue;
        nb_ports_available++;
        dump_port = portid;
    }

    if (nb_ports_available == 0) {
        rte_exit(EXIT_FAILURE, "All available ports are disabled. Please set portmask.\n");
    }

    if (nb_ports_available > 1) {
            rte_exit(EXIT_FAILURE, "Only support one port dump.\n");
    }

    unsigned available_icore = rte_lcore_count();
    if(available_icore != 1){
        rte_exit(EXIT_FAILURE, "Onlu support one core dumpe - bye\n");
    }

    output_fd = fopen(OUTPUT_FILE, "w");
    if(output_fd == NULL){
        rte_exit(EXIT_FAILURE, "Could not open out put file ! %s\n", OUTPUT_FILE);
    }

    ret = rte_eth_dev_configure(dump_port, 1, 1, &port_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                      ret, (unsigned) dump_port);

    pktmbuf_pool  = rte_mempool_create("mbuf_pool", NB_MBUF,
                           MBUF_SIZE, 32,
                           sizeof(struct rte_pktmbuf_pool_private),
                           rte_pktmbuf_pool_init, NULL,
                           rte_pktmbuf_init, NULL,
                           rte_lcore_to_socket_id(rte_get_master_lcore()), 0);

    ret = rte_eth_rx_queue_setup(dump_port, 0, nb_rxd,rte_eth_dev_socket_id(dump_port), &rx_conf, pktmbuf_pool);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret, (unsigned) dump_port);

    ret = rte_eth_tx_queue_setup(dump_port, 0, nb_rxd, rte_eth_dev_socket_id(dump_port), &tx_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n", ret, (unsigned) dump_port);

    ret = rte_eth_dev_start(dump_port);
    if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                          ret, (unsigned) dump_port);
    rte_eth_promiscuous_enable(dump_port);

    check_all_ports_link_status(nb_ports, nis_package_dump_enabled_port_mask);

    /* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(nis_package_dump_launch_one_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            return -1;
    }

    return 0;
}

