
#ifndef _NIS_DNS_H_
#define _NIS_DNS_H_

#include <stdint.h>
#include <rte_ip.h>
#include <rte_udp.h>

//  默认端口53，需要高低位转换
#define DNS_SERVICE_PORT 13568

#define DNS_PROCESS_SUCCESS 0
#define DNS_INVALID_PACKAGE 1

#define DNS_TYPE_A 					0x0100
#define DNS_TYPE_CNMAE			0x0500
#define DNS_TYPE_MX					0x0F00
#define DNS_CLASS_DEFAULT 	0x0100

struct dns_header {
	uint16_t transiation_id;
	uint16_t flags;
	uint16_t question_count;
	uint16_t answer_count;
	uint16_t authority_count;
	uint16_t additional_count;
}__attribute__((__packed__));


struct dns_A_record{
	char domain[128];
	uint32_t hash;
	uint32_t ip;
}__rte_cache_aligned;

#define Is_DNS_Answer(dns_header)  (dns_header->flags & 0x80 )
#define get_DNS_OpCode(dns_header)  ((dns_header->flags >> 11) & 0xF)
#define get_DNS_Authoritative_Ansewer(dns_header) ((dns_header->flags >> 10) & 0x1)
#define get_DNS_Truncation(dns_header) ((dns_header->flags >> 9) & 0x1)
#define get_DNS_Recursion_Desired(dns_header) ((dns_header->flags >> 8) & 0x1)
#define get_DNS_Recursion_Available(dns_header) ((dns_header->flags >> 7) & 0x1)
#define get_DNS_Reserved(dns_header) ((dns_header->flags >> 6) & 0x1)
#define get_DNS_Return_Code(dns_header) (dns_header->flags  & 0xF)

// return code
#define DNS_RETURN_CODE_SUCCESS							0
#define DNS_RETURN_CODE_ILLEGAL_FORMATE		1
#define DNS_RETURN_CODE_SERVER_ERROR				2
#define DNS_RETURN_CODE_NAME_ERROR					3
#define DNS_RETURN_CODE_NOT_SUPPORT				4
#define DNS_RETURN_CODE_DNS_DISABLE		            5

// 初始化一些dns response里面比较通用的字段
void prepareDNSResponse(struct rte_mbuf* response);

// 处理dns request, 并构造返回的response
uint8_t processDNSRequest(struct rte_mbuf* request, struct rte_mbuf* response);

#endif /* DNS_H_ */
