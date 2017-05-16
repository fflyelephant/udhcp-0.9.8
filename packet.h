#ifndef _PACKET_H
#define _PACKET_H

#include <netinet/udp.h>
#include <netinet/ip.h>

struct dhcpMessage {
	u_int8_t op;			/* 1 for client,2 for server */
	u_int8_t htype;		    /* Ethernet Type (0x01)*/
	u_int8_t hlen;			/* Ethernet Len(6) */
	u_int8_t hops;			/* 若封包需要router传输,每经过一条加1,同一网段下为0 */
	u_int32_t xid;			/* transaction ID 客户端产生的事务ID用来标识一次DHCP C/S交互 */
	u_int16_t secs;			/* 客户端启动耗时(一般为0) */
	u_int16_t flags;		/* 0-15 bit 最低bit为1则server将以广播形式发包给client,其它未使用 */
	u_int32_t ciaddr;		/* 若client想继续使用之前获得的IP则填充在这(一般是client 的Inform包会填写) */
	u_int32_t yiaddr;		/* server回复client你可使用的IP(ACK,offer报文中填写) */
	u_int32_t siaddr;		/* 若client需要通过网络开机,从server发出的报文这里应该填写开机程序代码
							   所在的server地址 */
	u_int32_t giaddr;		/* 若需要跨网域进行DHCP发包,这里填写server发包的目的地址
							   (如果没有server一般是发给租赁出去的IP地址) */
	u_int8_t chaddr[16];	/* client的硬件地址 */
	u_int8_t sname[64];		/* server 的主机名 */
	u_int8_t file[128];		/* 若client需要通过网络开机,这里将填写开机程序名称,让后以TFTP传输 */
	u_int32_t cookie;		/* should be 0x63825363 */
	u_int8_t options[308];  /* 312 - cookie */ 
};

struct udp_dhcp_packet {
	struct iphdr ip;
	struct udphdr udp;
	struct dhcpMessage data;
};

void init_header(struct dhcpMessage *packet, char type);
int get_packet(struct dhcpMessage *packet, int fd);
u_int16_t checksum(void *addr, int count);
int raw_packet(struct dhcpMessage *payload, u_int32_t source_ip, int source_port,
		   u_int32_t dest_ip, int dest_port, unsigned char *dest_arp, int ifindex);
int kernel_packet(struct dhcpMessage *payload, u_int32_t source_ip, int source_port,
		   u_int32_t dest_ip, int dest_port);


#endif
