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
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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
  uint16_t ethtype = ethertype(packet);
  switch(ethtype) {
 		case ethertype_arp:
			sr_handle_arp(sr, packet+sizeof(sr_ethernet_hdr_t), len-sizeof(sr_ethernet_hdr_t), interface);
      break;
    case ethertype_ip:
      /* check min length */
      sr_handle_ip(sr, packet+sizeof(sr_ethernet_hdr_t), len-sizeof(sr_ethernet_hdr_t));
      break;
  }
}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: sr_handle_arp(struct sr_instance* sr, uint8_t * buf, unsigned int len, char* interface)
 * Scope:  Global
 *
 * This method handles the handling of arp packets, either forwarding, replying, etc.
 *
 *---------------------------------------------------------------------*/
void sr_handle_arp(struct sr_instance* sr, uint8_t * buf, unsigned int len, char* interface) {
	sr_arp_hdr_t* arp = (sr_arp_hdr_t*) buf;
	sr_arp_opcode op = (sr_arp_opcode)ntohs(arp->ar_op);
	switch(op) {
		case arp_op_request : 
			//send arp_reply;
			break;
		case arp_op_reply :
			//do something
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
	sr_ip_hdr_t* ip = (sr_ip_hdr_t*)buf;
  uint16_t rcv_cksum = ntohs(ip->ip_sum);
  ip->ip_sum = 0;  
  print_hdrs(packet, len);
  uint16_t cal_cksum = cksum(ip,len);  
	if(rcv_cksum != cal_cksum) {
		printf("***checksum mismatch***\n");
	} else {
		uint8_t ttl = ntohs(ip->ip_ttl)-1;
		if(ttl == 0) {
			/* ICMP packet: timeout */
		} else {
			ip->ip_ttl = htons(ttl);
			ip->cksum = htons(cksum(ip, len));
			/* IP packet manipulation complete */
			uint32_t addr = ntohs(ip->ip_dst);
		}
	}
}
/* 
	check if router is not destination
	//if(router IP(s) is not destination){
		//check min length
		//TTL handle/decrement, recalc ip chksum
		//check routing table for longest prefix match to get next hop IP/interface
		//check ARP cache for next hop MAC for next hop IP
			//if(miss)
				//send arp request add to queue
				//resend request until timeout or reply
			//else hit
				//send packet	
 	//else destined for router interface
		//if echo request, send ICMP echo_reply
		//if echo reply, print cause it's prolly error
		//if TCP/UDP payload, discard and send ICMP port unreachable type 3 code 3
		//if ARP request, send ARP reply
		//if ARP reply, pass to ARP cache to cache and remove from queue*/

