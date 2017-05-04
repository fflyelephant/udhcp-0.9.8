/* 
 * leases.c -- tools to manage DHCP leases 
 * Russ Dill <Russ.Dill@asu.edu> July 2001
 */

#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "debug.h"
#include "dhcpd.h"
#include "files.h"
#include "options.h"
#include "leases.h"
#include "arpping.h"

unsigned char blank_chaddr[] = {[0 ... 15] = 0};

/* 
	clear every lease out that chaddr OR yiaddr matches and is nonzero 
	遍历leases链表找到chaddr或yiaddr对应的节点,将节点置0.
*/
void clear_lease(u_int8_t *chaddr, u_int32_t yiaddr)
{
	unsigned int i, j;
	
	for (j = 0; j < 16 && !chaddr[j]; j++);
	/* j==16 表示chaddr数组为空,只需要比较yiaddr(小技巧) */

	for (i = 0; i < server_config.max_leases; i++)
		if ((j != 16 && !memcmp(leases[i].chaddr, chaddr, 16)) ||
		    (yiaddr && leases[i].yiaddr == yiaddr)) {
			memset(&(leases[i]), 0, sizeof(struct dhcpOfferedAddr));
		}
}


/* 
	add a lease into the table, clearing out any old ones 
	先清空chaddr,yiaddr对应的链表节点,找到最早到期的节点,将新节点赋值到最早到期的节点位置
	如果没有到期的IP则返回NULL
*/
struct dhcpOfferedAddr *add_lease(u_int8_t *chaddr, u_int32_t yiaddr, unsigned long lease)
{
	struct dhcpOfferedAddr *oldest;
	
	/* clean out any old ones */
	clear_lease(chaddr, yiaddr);
		
	oldest = oldest_expired_lease();
	
	if (oldest) {
		memcpy(oldest->chaddr, chaddr, 16);
		oldest->yiaddr = yiaddr;
		oldest->expires = time(0) + lease;
	}
	
	return oldest;
}


/* 
	true if a lease has expired 
	IP租赁到期返回true否则返回false
*/
int lease_expired(struct dhcpOfferedAddr *lease)
{
	return (lease->expires < (unsigned long) time(0));
}	


/*
	Find the oldest expired lease, NULL if there are no expired leases 
	找到leases链表中最早到期的节点,返回节点地址.没有到期节点返回NULL
*/
struct dhcpOfferedAddr *oldest_expired_lease(void)
{
	struct dhcpOfferedAddr *oldest = NULL;
	unsigned long oldest_lease = time(0);
	unsigned int i;

	
	for (i = 0; i < server_config.max_leases; i++)
		if (oldest_lease > leases[i].expires) {
			oldest_lease = leases[i].expires;
			oldest = &(leases[i]);
		}
	return oldest;
		
}


/* 
	Find the first lease that matches chaddr, NULL if no match 
	通过chaddr值找到leases中节点,返回节点地址.
*/
struct dhcpOfferedAddr *find_lease_by_chaddr(u_int8_t *chaddr)
{
	unsigned int i;

	for (i = 0; i < server_config.max_leases; i++)
		if (!memcmp(leases[i].chaddr, chaddr, 16)) return &(leases[i]);
	
	return NULL;
}


/*
	Find the first lease that matches yiaddr, NULL is no match 
	通过yiaddr值找到leases中节点,返回节点地址.
*/
struct dhcpOfferedAddr *find_lease_by_yiaddr(u_int32_t yiaddr)
{
	unsigned int i;

	for (i = 0; i < server_config.max_leases; i++)
		if (leases[i].yiaddr == yiaddr) return &(leases[i]);
	
	return NULL;
}


/* find an assignable address, it check_expired is true, we check all the expired leases as well.
 * Maybe this should try expired leases by age... 
 * 在地址池中返回一个没有被分配的地址.
*/
u_int32_t find_address(int check_expired) 
{
	u_int32_t addr, ret;
	struct dhcpOfferedAddr *lease = NULL;		

	addr = ntohl(server_config.start); /* addr is in host order here */
	for (;addr <= ntohl(server_config.end); addr++) {

		/* 排除地址池中.0和.255结尾的地址 */
		/* ie, 192.168.55.0 */
		if (!(addr & 0xFF)) continue;

		/* ie, 192.168.55.255 */
		if ((addr & 0xFF) == 0xFF) continue;

		/* lease is not taken */
		ret = htonl(addr);
		if ((!(lease = find_lease_by_yiaddr(ret)) ||

		     /* or it expired and we are checking for expired leases */
		     (check_expired  && lease_expired(lease))) &&

		     /* and it isn't on the network */
	    	     !check_ip(ret)) {
			return ret;
			break;
		}
	}
	return 0;
}


/* 
	check is an IP is taken, if it is, add it to the lease table 
	检测此地址是否有在被其它lan pc所使用,检测的方式是用此IP广播arp报文,
	根据是否有回应判断此IP是否被占用.(比如某个lan pc 是使用的static IP,
	且此IP在udhcpd的地址池中,在udhcpd分配ip给客户端时必须做此检查(检查有就要将此IP添加到leases链表中表示已被分配),
	否则会造成IP冲突).
*/
int check_ip(u_int32_t addr)
{
	struct in_addr temp;
	/* arpping 发送一个arp广播包,经过一段时间等待后如果此IP没有被局域网内的主机使用就收不到单播回复,返回1 */	
	if (arpping(addr, server_config.server, server_config.arp, server_config.interface) == 0) {
		temp.s_addr = addr;
	 	LOG(LOG_INFO, "%s belongs to someone, reserving it for %ld seconds", 
	 		inet_ntoa(temp), server_config.conflict_time);
	 	/* 
	 		blank_chaddr 黑户? 因为不知道使用这个IP的主机的MAC地址 
			如果有主机回应arp,完全可以获得IP所对应的MAC地址，这里应该是不关心这个MAC了，所以
			MAC全部记为0
	 	*/
		add_lease(blank_chaddr, addr, server_config.conflict_time);
		return 1;
	} else return 0;
}

