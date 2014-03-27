/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*
 * local functions
 */

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d on interface %s \n",len, interface);
	/* copy packet */
  uint16_t ethtype = ethertype(packet);
  switch(ethtype) {
 		case ethertype_arp:
			sr_handle_arp(sr, packet+sizeof(sr_ethernet_hdr_t), len-sizeof(sr_ethernet_hdr_t), interface);
      break;
    case ethertype_ip:
      sr_handle_ip(sr, packet+sizeof(sr_ethernet_hdr_t), len-sizeof(sr_ethernet_hdr_t));
      break;
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handle_arp(struct sr_instance* sr, uint8_t * buf, 
 * 							unsigned int len, char* interface)
 * Scope:  Global
 *
 * This method handles the handling of arp packets, either forwarding, replying, etc.
 * interface = name_version (e.g. "eth1")
 *---------------------------------------------------------------------*/
void sr_handle_arp(struct sr_instance* sr, uint8_t * buf, unsigned int len, char* interface) {
	sr_arp_hdr_t* arp = (sr_arp_hdr_t*) buf;
	enum sr_arp_opcode op = (enum sr_arp_opcode)ntohs(arp->ar_op);
	struct sr_if* iface = sr_get_interface(sr, interface);
	switch(op) {
		case arp_op_request : 
			printf("Sending ARP reply\n");
			send_arp_rep(sr, iface, arp);
			break;
		case arp_op_reply :
			/* add mac and ip mapping */
			printf("Updating arp cache\n");
			sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip);
			/* sr_arpreq_destroy is handled in arpcache */
			break;
	}
}

/*---------------------------------------------------------------------
 * Method: sr_handle_ip(struct sr_instance* sr, uint8_t * buf, unsigned int len)
 * Scope:  Global
 *
 * This method handles the handling of ip packets, either forwarding, replying, etc.
 * This also includes calculating the checksum
 *
 *---------------------------------------------------------------------*/
void sr_handle_ip(struct sr_instance* sr, uint8_t * buf, unsigned int len) {
  printf("IP\n");
	sr_ip_hdr_t* ip = (sr_ip_hdr_t*)buf;
	/* check min length */
	if(len < sizeof(sr_ip_hdr_t)) {
		printf("Packet too small to be valid\n");
		return;
	}
  uint16_t rcv_cksum = ntohs(ip->ip_sum);
  ip->ip_sum = 0;  
  uint16_t cal_cksum = cksum(ip,sizeof(sr_ip_hdr_t));  
	if(rcv_cksum != cal_cksum) {
		printf("***checksum mismatch***\n");
		/* discard packet */
	} else {
		printf("***checksum match***\n");
		uint8_t ttl = ntohs(ip->ip_ttl); /* check if zero */
		if(ttl <= 1) {
			/* send ICMP packet: timeout */
			printf("packet timed out\n");
			send_icmp_pkt(sr, buf, icmp_time_exceeded, icmp_ttl_exceeded);
		} else {
			ip->ip_ttl = htons(ttl - 1);
			ip->ip_sum = htons(cksum(ip, len));
			/* IP packet manipulation complete */
			uint32_t addr = ntohs(ip->ip_dst);
			struct sr_if* local_interface = sr->if_list;
			while(addr != local_interface->ip && local_interface != 0) {
				local_interface = local_interface->next;
			}
			if(local_interface != 0) {
				printf("packet sent to local addr\n");
				if(ip->ip_p == ip_protocol_icmp) {
					/*struct sr_icmp_hdr_t* icmp = (sr_icmp_hdr_t*)(buf + sizeof(sr_ip_hdr_t));
					if(icmp->icmp_type == icmp_echo) {
						send_icmp_pkt(sr, buf, icmp_echo_reply, 0);
						printf("echo request\n");
					}*/
				} else {
					/* TCP/UDP payload, discard and send ICMP port unreachable type 3 code 3 */
					send_icmp_pkt(sr, buf, icmp_unreachable, icmp_port);
				}
			} else {
				/*check routing table for longest prefix match to get next hop IP/interface*/
				struct in_addr in_ip;
				in_ip.s_addr = ip->ip_dst;
				struct sr_rt* nxt_hp = sr_rt_search(sr, in_ip);
				/* check ARP cache for next hop MAC for next hop IP */
				if(nxt_hp == 0) {
					/* send ICMP net unreachable */
				} else {
					struct sr_arpentry* cache_ent = sr_arpcache_lookup(&sr->cache, (uint32_t)nxt_hp->dest.s_addr);
					if(cache_ent == 0) {
						/* cache miss, send arp_req */
						sr_arpcache_queuereq(&sr->cache, (uint32_t)nxt_hp->dest.s_addr,buf, len, nxt_hp->interface);
					} else {
						/* ARP cache hit */
						/* send packet */
						printf("*********** ERROR: ARP Cache hit without request *********\n");
					}
				}
			}	
		}
	}
	free(buf);
}
int send_arp_req(struct sr_instance* sr, struct sr_arpreq* arp_req){
    uint8_t* block = malloc(sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t));
	sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)block;
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(block+sizeof(sr_ethernet_hdr_t));
	struct sr_if* arp_if = sr_get_interface(sr, arp_req->packets->iface);

    /* modify/populate ARP header */
	arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
	arp_hdr->ar_hln = ETHER_ADDR_LEN;
	arp_hdr->ar_pln = sizeof(uint32_t);
	arp_hdr->ar_op  = htons(arp_op_request);
	memcpy(arp_hdr->ar_sha, arp_if->addr, ETHER_ADDR_LEN);
	arp_hdr->ar_sip = arp_if->ip;
	memcpy(arp_hdr->ar_tha, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
	arp_hdr->ar_tip = arp_req->ip;

    /* modify/populate MAC header */
    memcpy(eth_hdr->ether_dhost, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, arp_if->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);
	int ret = sr_send_packet(sr, (uint8_t*)(arp_hdr), sizeof(*arp_hdr), "\xff\xff\xff\xff\xff\xff");
	free(block);
	return ret;
}

int send_arp_rep(struct sr_instance* sr, struct sr_if* req_if, sr_arp_hdr_t* req){
    uint8_t* block = malloc(sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t));
	sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(block+sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(block);

    /* modify/populate ARP header */
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(0x0800);
	arp_hdr->ar_hln = ETHER_ADDR_LEN;
	arp_hdr->ar_pln = sizeof(uint32_t);
	arp_hdr->ar_op  = htons(arp_op_reply);
	memcpy(arp_hdr->ar_sha, req_if->addr, ETHER_ADDR_LEN);
	arp_hdr->ar_sip = req_if->ip;
	memcpy(arp_hdr->ar_tha, req->ar_sha, ETHER_ADDR_LEN);
	arp_hdr->ar_tip = req->ar_sip;

    /* modify/populate MAC header */
    memcpy(eth_hdr->ether_dhost, req->ar_sha, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, req_if->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);

	int ret = sr_send_packet(sr, block, sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t), req_if->name);
    if(ret != 0) { printf("ARP failed to send\n"); }
	free(block);
	return ret;
}

int send_icmp_pkt(struct sr_instance* sr, uint8_t* buf, uint8_t type, uint8_t code) {
	uint8_t* block = 0;
	switch(type) {
		case icmp_unreachable:
			block = malloc(sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
			sr_icmp_t3_hdr_t* icmp_error = (sr_icmp_t3_hdr_t*)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			icmp_error->icmp_type = type;
			icmp_error->icmp_code = code;
			icmp_error->icmp_sum  = 0;
			icmp_error->unused = 0;
			icmp_error->next_mtu = 0;
			memcpy(icmp_error->data, buf, ICMP_DATA_SIZE);
			icmp_error->icmp_sum = cksum(icmp_error, sizeof(sr_icmp_t3_hdr_t));
			break;
		case icmp_echo_reply:
			block = malloc(sizeof(sr_icmp_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
			sr_icmp_hdr_t* icmp_echo = (sr_icmp_hdr_t*)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			icmp_echo->icmp_type = type;
			icmp_echo->icmp_code = code;
			icmp_echo->icmp_sum  = 0;
			icmp_echo->icmp_sum = cksum(icmp_echo, sizeof(sr_icmp_hdr_t));
			break;
		case icmp_time_exceeded:
			block = malloc(sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t));
			sr_icmp_t3_hdr_t* icmp_timeout = (sr_icmp_t3_hdr_t*)(block + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			icmp_timeout->icmp_type = type;
			icmp_timeout->icmp_code = code;
			icmp_timeout->icmp_sum  = 0;
			icmp_timeout->unused = 0;
			icmp_timeout->next_mtu = 0;
			memcpy(icmp_timeout->data, buf, ICMP_DATA_SIZE);
			icmp_timeout->icmp_sum = cksum(icmp_timeout, sizeof(sr_icmp_t3_hdr_t));
			break;
		default:
			/* shouldn't arrive here in our system setup */
			break;
	}
	/* populate IP header */
	sr_ip_hdr_t* ip_icmp_error = (sr_ip_hdr_t*)(block+sizeof(sr_ethernet_hdr_t));
	ip_icmp_error->ip_hl = sizeof(sr_ip_hdr_t);
	ip_icmp_error->ip_v  = 4;
	ip_icmp_error->ip_tos = 0x0000;
	if(type == icmp_unreachable || type == icmp_time_exceeded) {
		ip_icmp_error->ip_len = sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t);
	} else {
		ip_icmp_error->ip_len = sizeof(sr_icmp_hdr_t)+sizeof(sr_ip_hdr_t);
	}
	ip_icmp_error->ip_id 	= ((sr_ip_hdr_t*)(buf))->ip_id;
	ip_icmp_error->ip_off = htons(IP_DF);
	ip_icmp_error->ip_ttl = IP_TTL; 
	ip_icmp_error->ip_p 	= ip_protocol_icmp;
	ip_icmp_error->ip_dst = ((sr_ip_hdr_t*)(buf))->ip_src;
	struct in_addr i;
	i.s_addr = ip_icmp_error->ip_dst;
	char* iface = (sr_rt_search(sr, i))->interface;
	ip_icmp_error->ip_src =  sr_get_interface(sr, iface)->ip;
	ip_icmp_error->ip_sum = 0;
	ip_icmp_error->ip_sum = cksum(ip_icmp_error, sizeof(sr_ip_hdr_t));
	/* add to arp req queue */
	sr_arpcache_queuereq(&sr->cache, ip_icmp_error->ip_dst, block, sizeof(block), iface);
	return 0;
}
