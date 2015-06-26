#include <string.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include "dns.h"

static inline uint16_t
get_16b_sum(uint16_t *ptr16, uint32_t nr)
{
	uint32_t sum = 0;
	while (nr > 1)
	{
		sum +=*ptr16;
		nr -= sizeof(uint16_t);
		ptr16++;
		if (sum > UINT16_MAX)
			sum -= UINT16_MAX;
	}

	/* If length is in odd bytes */
	if (nr)
		sum += *((uint8_t*)ptr16);

	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	sum &= 0x0ffff;
	return (uint16_t)sum;
}

static inline uint16_t
get_ipv4_psd_sum (struct ipv4_hdr * ip_hdr)
{
	/* Pseudo Header for IPv4/UDP/TCP checksum */
	union ipv4_psd_header {
		struct {
			uint32_t src_addr; /* IP address of source host. */
			uint32_t dst_addr; /* IP address of destination host(s). */
			uint8_t  zero;     /* zero. */
			uint8_t  proto;    /* L4 protocol type. */
			uint16_t len;      /* L4 length. */
		} __attribute__((__packed__));
		uint16_t u16_arr[0];
	} psd_hdr;

	psd_hdr.src_addr = ip_hdr->src_addr;
	psd_hdr.dst_addr = ip_hdr->dst_addr;
	psd_hdr.zero     = 0;
	psd_hdr.proto    = ip_hdr->next_proto_id;
	psd_hdr.len      = rte_cpu_to_be_16((uint16_t)(rte_be_to_cpu_16(ip_hdr->total_length)
				- sizeof(struct ipv4_hdr)));
	return get_16b_sum(psd_hdr.u16_arr, sizeof(psd_hdr));
}

static inline uint16_t get_ipv4_udptcp_checksum(struct ipv4_hdr *ipv4_hdr, uint16_t *l4_hdr)
{
	uint32_t cksum;
	uint32_t l4_len;

	l4_len = rte_be_to_cpu_16(ipv4_hdr->total_length) - sizeof(struct ipv4_hdr);

	cksum = get_16b_sum(l4_hdr, l4_len);
	cksum += get_ipv4_psd_sum(ipv4_hdr);

	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
	cksum = (~cksum) & 0xffff;
	if (cksum == 0)
		cksum = 0xffff;
	return (uint16_t)cksum;
}

static  inline  uint16_t get_ipv4_cksum(struct ipv4_hdr *ipv4_hdr){
	  	uint16_t cksum;
	  	cksum = get_16b_sum((uint16_t*)ipv4_hdr, sizeof(struct ipv4_hdr));
	  	return (uint16_t)((cksum == 0xffff)?cksum:~cksum);
 }

void prepareDNSResponse(struct rte_mbuf* response)
  {
	  		struct ether_hdr *response_eth;
	  		struct ipv4_hdr *response_ip;
	  		struct udp_hdr  *response_udp;
	  		struct dns_header *response_dns;
	  	    response->pkt.next = NULL;
	  		response_eth = (struct ether_hdr *)rte_pktmbuf_mtod(response, struct ether_hdr *);
	  		response_ip = (struct ipv4_hdr *)( (unsigned char *)response_eth + sizeof(struct ether_hdr));
	  		response_udp = (struct udp_hdr *)( (unsigned char *)response_ip + sizeof(struct ipv4_hdr));
	  		response_dns =  (struct dns_header *)( (unsigned char *)response_udp + sizeof(struct udp_hdr));
	  		response_eth->ether_type = 8;
	  		response_ip->version_ihl = 0x45; //version 4, header length 5
	  		response_ip->type_of_service = 0;
	  		response_ip->packet_id = 0x1234;
	  		response_ip->fragment_offset = 0;
	  		response_ip->time_to_live = 128;
	  		response_ip->next_proto_id = IPPROTO_UDP;
	  		response_udp->src_port = DNS_SERVICE_PORT;
	  		response_dns->additional_count = 0; // 这个是从其他服务器获取的对应记录
	  		response_dns->authority_count = 0; // 这个是返回域名下级dns查询服务地址，做递归查询
	  		response_dns->flags = 0x8000;
  }


  static unsigned char* parseQuestion(unsigned char* domain, unsigned char* querydata, uint16_t* type, uint16_t* class){
  	   size_t copysize = (uint8_t) (*querydata);
  		querydata++;
  		while(1){
  			memcpy(domain,querydata, copysize);
  			querydata += copysize;
  			domain += copysize;
  			copysize =  (uint8_t) (*querydata);
  			querydata++;
  			if(copysize ==  0){
  				break;
  			}else{
  				*domain = '.';
  				domain++;
  			}
  		}
  		*domain = 0;
  		domain++;
  		*type =   *(uint16_t*) querydata;
  		querydata += 2;
  		*class =   *(uint16_t*) querydata;
  		querydata += 2;
  		return querydata;
  }

 static unsigned char* prepareAnswer(unsigned char* query, unsigned char* response, uint8_t queryOffset, uint8_t* answerCount, uint16_t type,uint16_t class ){
	  // 这里暂时先强制性返回一个AName的 record
	 printf("prepare answre for %s, %u , %u\n", query, type, class);
	  *response = 0xC0;
	  response++;
	  *response = queryOffset + sizeof(struct dns_header) ;
	  response++;
	  *(uint16_t*)(response) = DNS_TYPE_A;
	  response += 2;
	  *(uint16_t*)(response) = DNS_CLASS_DEFAULT;
	  response += 2;
	  *(uint32_t*)(response)  = 0x58020000; // seconds
	  response+= 4;
	  *(uint32_t*)(response)  = 0x0400; // seconds
	  response+=2;
	  *(uint32_t*)(response)  = rte_cpu_to_be_32(0x73efd21b);
	  response+=4;
	  (*answerCount)++;
	  return response;
 }




  uint8_t processDNSRequest(struct rte_mbuf* request, struct rte_mbuf* response){
		unsigned char tmp[1024];
		uint8_t j, answerCount;
		uint16_t type, class,queryCount;
		struct ether_hdr *request_eth, *response_eth;
		struct ipv4_hdr *request_ip, *response_ip;
		struct udp_hdr *request_udp, *response_udp;
		struct dns_header *request_dns, *response_dns;
		 uint16_t response_data_len;

		response_eth = (struct ether_hdr *)rte_pktmbuf_mtod(response, struct ether_hdr *);
		response_ip = (struct ipv4_hdr *)( (unsigned char *)response_eth + sizeof(struct ether_hdr));
		response_udp = (struct udp_hdr *)( (unsigned char *)response_ip + sizeof(struct ipv4_hdr));
		response_dns =  (struct dns_header *)( (unsigned char *)response_udp + sizeof(struct udp_hdr));
		request_eth = rte_pktmbuf_mtod(request, struct ether_hdr *);
			if (likely(request_eth->ether_type == 8)) {
				request_ip = (struct ipv4_hdr *)( (unsigned char *)request_eth + sizeof(struct ether_hdr));
				if(request_ip->next_proto_id == IPPROTO_UDP){
					request_udp =  (struct udp_hdr *)( (unsigned char *)request_ip + sizeof(struct ipv4_hdr));
					if(request_udp->dst_port == DNS_SERVICE_PORT){
#ifdef NIS_DEBUG
						// debug 时候输出下整个dns query包的内容
						unsigned char* end = (unsigned char*)(rte_pktmbuf_mtod(request, unsigned char *)) + rte_pktmbuf_data_len(request);
						unsigned char * output = (unsigned char *) request_eth ;
						printf(" receive package\n");
						while(output < end){
							printf(" %x", (uint8_t)*output);
							output ++;
						}
						printf("\n");
#endif

						request_dns =  (struct dns_header *)( (unsigned char *)request_udp + sizeof(struct udp_hdr));;
						if(likely(!Is_DNS_Answer(request_dns))){
							// prepare response data
							memcpy((void*)&response_eth->s_addr, (void*)&request_eth->d_addr, sizeof(struct ether_addr));
							memcpy((void*)&response_eth->d_addr, (void*)&request_eth->s_addr, sizeof(struct ether_addr));
							response_ip->src_addr =  request_ip->dst_addr;
							response_ip->dst_addr =  request_ip->src_addr;
							response_udp->dst_port = request_udp->src_port;
							response_dns->transiation_id = request_dns->transiation_id;
							response_dns->question_count = request_dns->question_count;

							// process request
							unsigned char* endpoint = (unsigned char*)(rte_pktmbuf_mtod(request, unsigned char *)) + rte_pktmbuf_data_len(request);
							unsigned char * queryStart = ((unsigned char *)request_dns) + sizeof(struct dns_header);
							unsigned char* queryPostion = queryStart;
							queryCount = rte_cpu_to_be_16(request_dns->question_count);

							// 首先拷贝整个问题区域到response
							unsigned char* responseStart = ((unsigned char *)response_dns) + sizeof(struct dns_header);
							unsigned char* responsePostion = responseStart;
							j = 0;
							while(j < queryCount && queryPostion <= endpoint){

								queryPostion = parseQuestion(tmp, queryPostion, &type, &class );
							} // end if while test
							memcpy(responsePostion, queryStart,  queryPostion -  queryStart); // copy query
							responsePostion += (queryPostion -  queryStart);

							// 接着依次处理所有问题
							j = 0;
							answerCount = 0;
							queryPostion = queryStart;
							while(j < queryCount && queryPostion <= endpoint){
								j++;
								unsigned char*  newPostion = parseQuestion(tmp, queryPostion, &type, &class );
								responsePostion = prepareAnswer(tmp, responsePostion, queryPostion - queryStart, &answerCount, type, class);
								queryPostion = newPostion;
								printf("receive dns query, domian = %s,   type = %u,   class = %u \n", tmp, type, class);
							} // end if while test

							// package length and checkesum to set for ip header
							response_data_len =  responsePostion -  responseStart + sizeof(struct dns_header);

							// 做最后的封包和数据校验
							response_dns->answer_count = rte_cpu_to_be_16(answerCount);
							response_udp->dgram_len = rte_cpu_to_be_16(response_data_len + sizeof(struct udp_hdr));
							response_ip->total_length = rte_cpu_to_be_16(response_data_len + sizeof(struct udp_hdr) + sizeof(struct ipv4_hdr));
							response->pkt.data_len = response_data_len + sizeof(struct udp_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct ether_hdr );
							response_udp->dgram_cksum = 0;
							response_udp->dgram_cksum = get_ipv4_udptcp_checksum(response_ip,(uint16_t*)response_udp);
							response_ip->hdr_checksum = 0;
							response_ip->hdr_checksum = get_ipv4_cksum(response_ip);

#ifdef NIS_DEBUG
							unsigned char * output = (unsigned char *) response_eth ;
							printf(" send  package : %u, %p,  %p\n", response_data_len, output, responsePostion);
							while(output < responsePostion){
								printf(" %x", (uint8_t)*output);
								output ++;
							}
							printf("\n");
#endif
							return DNS_PROCESS_SUCCESS;
						} // end if dns query test
					} // end if dns test
				} //end if udp test
			}// end if ether type
			return DNS_INVALID_PACKAGE;
  }
