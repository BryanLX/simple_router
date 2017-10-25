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
#include <stdlib.h>
#include <string.h>
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



void send_icmp_3(struct sr_instance* sr, int type, int code , uint8_t* packet, char* interface, unsigned int len){
    printf("Sending ICMP 3 \n");
    /* Get nessary informations*/
    struct sr_if *iface = sr_get_interface(sr, interface);
    sr_ethernet_hdr_t * e_header_ori = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t * ip_header_ori = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /*Allocate a packet*/
    uint8_t* icmp = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    sr_ethernet_hdr_t *e_header = (sr_ethernet_hdr_t *) icmp;
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (icmp + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t* icmp_header = (sr_icmp_t3_hdr_t*) (icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /*Setting ethernet header*/
    memcpy(e_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
    memcpy(e_header->ether_dhost, e_header_ori->ether_shost, ETHER_ADDR_LEN);
    e_header->ether_type = htons(ethertype_ip);

    /*Setting ip header*/
    ip_header ->ip_hl = ip_header_ori ->ip_hl;
    ip_header ->ip_v = ip_header_ori ->ip_v;
    ip_header ->ip_tos = ip_header_ori ->ip_tos;
    ip_header ->ip_len = htons(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t));
    ip_header ->ip_id = ip_header_ori->ip_id;
    ip_header ->ip_off = ip_header_ori->ip_off;
    ip_header ->ip_ttl = 64;
    ip_header ->ip_p = ip_protocol_icmp;
    ip_header ->ip_sum = 0;
    ip_header ->ip_src = iface->ip;
    ip_header ->ip_dst = ip_header_ori->ip_src;


    /*Setting ICMP*/
    icmp_header->icmp_type = type;
    icmp_header->unused = 0;
    icmp_header->next_mtu = 0;
    icmp_header->icmp_code = code;
    memcpy(icmp_header->data, ip_header_ori, ICMP_DATA_SIZE);
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum((const void*)icmp_header, sizeof(sr_icmp_t3_hdr_t));
    ip_header ->ip_sum = cksum((const void*)ip_header, sizeof(sr_ip_hdr_t));

    struct sr_arpentry * result = sr_arpcache_lookup(&sr->cache,ip_header ->ip_dst );
    if (result){
      memcpy(e_header->ether_dhost, result->mac, ETHER_ADDR_LEN);
      int re = sr_send_packet(sr, icmp, sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), interface);
      if (re != 0){
        printf("Something wrong when sending packet \n");
      }
      free(icmp);
    }else{
      struct sr_arpreq * req=sr_arpcache_queuereq(&sr->cache,ip_header ->ip_dst,icmp,sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),interface);
      handle_arpreq(sr,req);
    }
}

void send_icmp(struct sr_instance* sr, int type, int code , uint8_t* packet, char* interface, unsigned int len){
    printf("Sending ICMP \n");
    /* Get nessary informations*/
    struct sr_if *iface = sr_get_interface(sr, interface);
    sr_ethernet_hdr_t * e_header_ori = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t * ip_header_ori = (sr_ip_hdr_t *) (packet + sizeof(struct sr_ethernet_hdr));

    /*Allocate a packet*/
    uint8_t* icmp = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    sr_ethernet_hdr_t *e_header = (sr_ethernet_hdr_t *) icmp;
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (icmp + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*) (icmp + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /*Setting ethernet header*/
    memcpy(e_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
    memcpy(e_header->ether_dhost, e_header_ori->ether_shost, ETHER_ADDR_LEN);
    e_header->ether_type = htons(ethertype_ip);

    /*Setting ip header*/
    ip_header ->ip_hl = ip_header_ori ->ip_hl;
    ip_header ->ip_v = ip_header_ori ->ip_v;
    ip_header ->ip_tos = ip_header_ori ->ip_tos;
    ip_header ->ip_len = htons(sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t));
    ip_header ->ip_id = ip_header_ori->ip_id;
    ip_header ->ip_off = ip_header_ori->ip_off;
    ip_header ->ip_ttl = 64;
    ip_header ->ip_p = ip_protocol_icmp;
    ip_header ->ip_sum = 0;
    ip_header ->ip_src = iface->ip;
    ip_header ->ip_dst = ip_header_ori->ip_src;

    /*Setting ICMP*/
    icmp_header->icmp_type = type;
    icmp_header->icmp_code = code;
    icmp_header->icmp_sum = 0;
    icmp_header->icmp_sum = cksum((const void*)icmp_header, sizeof(sr_icmp_hdr_t));
    ip_header ->ip_sum = cksum((const void*)ip_header, sizeof(sr_ip_hdr_t));

    struct sr_arpentry * result = sr_arpcache_lookup(&sr->cache,ip_header ->ip_dst );
    if (result){
      memcpy(e_header->ether_dhost, result->mac, ETHER_ADDR_LEN);
      int re = sr_send_packet(sr, icmp, sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), interface);
      if (re != 0){
        printf("Something wrong when sending packet \n");
      }
      free(icmp);
    }else{
      struct sr_arpreq * req=sr_arpcache_queuereq(&sr->cache,ip_header ->ip_dst,icmp,sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),interface);
      handle_arpreq(sr,req);
    }

}

void send_arp(struct sr_instance *sr, struct sr_arpreq * req,struct sr_if* if_list){
    uint8_t* arp = (uint8_t*) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    printf("Sending arp broadcast, start processing..... \n");
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*) (arp+ sizeof(struct sr_ethernet_hdr));
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t*) arp;

    /* setting eth_header*/
    memset(eth_header->ether_dhost, 255, ETHER_ADDR_LEN);
    memcpy(eth_header->ether_shost, if_list->addr, ETHER_ADDR_LEN);
    eth_header->ether_type = htons(ethertype_arp);

    /* setting arp_header*/
    arp_header-> ar_hrd = htons(arp_hrd_ethernet);
    arp_header-> ar_pro = htons(ethertype_ip);
    arp_header-> ar_hln = ETHER_ADDR_LEN;
    arp_header-> ar_pln = 4;
    arp_header-> ar_op = htons(arp_op_request);
    memcpy(arp_header-> ar_sha, if_list->addr, ETHER_ADDR_LEN);
    arp_header-> ar_sip = if_list->ip;
    memset(arp_header-> ar_tha, 0,ETHER_ADDR_LEN);
    arp_header-> ar_tip = req->ip;
    print_hdrs(arp,sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    printf("Arp bordcast finished..... \n");
    int size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    int result =  sr_send_packet(sr, arp, size,if_list->name );
    if (result != 0){
      printf("Something wrong when sending packet \n");
    }
    free(arp);
}


struct sr_rt * LPM(struct sr_rt * r_table,uint32_t  ip_dst){


      struct sr_rt * result  = NULL;
      struct sr_rt * cur = r_table;
      uint32_t max =0;
      while(cur){
        uint32_t network_id = ntohl(ip_dst) & ntohl(cur->mask.s_addr);
        uint32_t cur_id = ntohl(cur->dest.s_addr) & ntohl(cur->mask.s_addr);
        if(network_id == cur_id){
            if(ntohl(cur->mask.s_addr) > max){
                printf("%u>%u \n",ntohl(cur->mask.s_addr),max);
                result = cur;
                max = ntohl(cur->mask.s_addr);
            }
        }
        cur = cur->next;
      }

      return result;

}



void sr_handlearp(struct sr_instance* sr,uint8_t * packet,unsigned int len,char* interface)
{
    sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *)packet;
    sr_arp_hdr_t* a_header = (sr_arp_hdr_t *) (sizeof(sr_ethernet_hdr_t)+packet);
    unsigned short op = a_header->ar_op;

    int me = 0;
    struct sr_if * temp = sr->if_list;
    struct sr_if * the_one = NULL;
    while (temp != NULL) {
        if (temp->ip == a_header->ar_tip){
          me = 1;
          the_one = temp;
          break;
        }
        temp = temp->next;
    }

    struct sr_if *iface = sr_get_interface(sr, interface);
    if (me == 0 ){
      return;
    }
    if(arp_op_request == ntohs(op) ){
      /* handle arp request*/
      printf("Received arp request, start processing..... \n");
      uint8_t *arp_reply = (uint8_t *)malloc(sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));

      sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*) (arp_reply + sizeof(struct sr_ethernet_hdr));
      sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t*) arp_reply;

      /* setting eth_header*/
      memcpy(eth_header->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN);
      memcpy(eth_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
      eth_header->ether_type = htons(ethertype_arp);

      /* setting arp_header*/
      arp_header-> ar_hrd = htons(arp_hrd_ethernet);
      arp_header-> ar_pro = htons(ethertype_ip);
      arp_header-> ar_hln = ETHER_ADDR_LEN;
      arp_header-> ar_pln = 4;
      arp_header-> ar_op = htons(arp_op_reply);
      memcpy(arp_header-> ar_sha, the_one->addr, ETHER_ADDR_LEN);
      arp_header-> ar_sip = the_one->ip;
      memcpy(arp_header-> ar_tha, a_header->ar_sha,ETHER_ADDR_LEN);
      arp_header-> ar_tip = a_header->ar_sip;

      int size = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
      printf("Sending reply: \n");
      print_hdr_eth(arp_reply);

      struct sr_arpentry * result = sr_arpcache_lookup(&sr->cache,a_header->ar_sip );
      if (result){
        memcpy(eth_header->ether_dhost, result->mac, ETHER_ADDR_LEN);
        int result =  sr_send_packet(sr, arp_reply, size, interface);
        if (result != 0){
          printf("Something wrong when sending packet \n");
        }
        free(arp_reply);
      }else{
        struct sr_arpreq * req=sr_arpcache_queuereq(&sr->cache,a_header->ar_sip,arp_reply,size,interface);
        handle_arpreq(sr,req);
      }
    }else if (arp_op_reply == ntohs(op) ){
      /* handle arp reply*/
        printf("Received arp reply, start processing..... \n");
        printf("kkkkkkkkkkk%u\n",sr->cache.requests->ip);
        printf("kkkkkkkkkkk%u\n",sr->cache.a_header->ar_sip);
        sr_arp_hdr_t* arp_header = (sr_arp_hdr_t *) (sizeof(sr_ethernet_hdr_t)+packet);
        struct sr_arpreq *request = sr_arpcache_insert(&sr->cache,arp_header->ar_sha, arp_header->ar_sip);
        if(request){
          struct sr_packet *p_node = request->packets;
          /* forwarding all packet are waiting */
          while(p_node){
            sr_ethernet_hdr_t * e_header = (sr_ethernet_hdr_t *)p_node->buf;
  					memcpy(e_header->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
  					memcpy(e_header->ether_shost, sr_get_interface(sr, p_node->iface)->addr, ETHER_ADDR_LEN);
  					int result = sr_send_packet(sr, p_node->buf, p_node->len, p_node->iface);
  					if (result !=0){
                printf("Waiting packet sending failed \n");
            }
  					p_node = p_node->next;
          }
          sr_arpreq_destroy(&sr->cache, request);
        }
    }else{
        printf("Unkown arp opcode \n");
    }
}


void sr_handleip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
      /* Get necessary informaiton*/
      struct sr_if *iface = sr_get_interface(sr, interface);
      sr_ethernet_hdr_t *e_header = (sr_ethernet_hdr_t*) packet;
      sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

      /* Check if it is send to me*/
      int me = 0;
      struct sr_if * temp = sr->if_list;
      struct sr_if * the_one = NULL;
	    while (temp != NULL) {
		      if (temp->ip == ip_header->ip_dst){
            me = 1;
            the_one = temp;
			      break;
          }
		      temp = temp->next;
	    }

      if (ip_header->ip_ttl <= 1 ){
          if(ip_header->ip_ttl == 1 &&  me ==1){

          }else{
          printf("Received ip with TTL less or equal to to  1, packet been dropped \n");

          send_icmp_3(sr, 11, 0, packet, interface, len);
          return;
        }
      }

      printf("ip_dis:%d \n  ,ifaceip: %d \n",ip_header->ip_dst,iface->ip);
      if (me == 1){
          printf("Received ip for me, start processing..... \n");
          if (ip_header->ip_p == ip_protocol_icmp){
            sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t* )(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            if(icmp_header->icmp_type == 8){
              printf("Received icmp echo , start processing..... \n");
              send_icmp(sr, 0, 0, packet, interface, len);

              return;
            }
          } else {
            printf("Sending port unreachable\n");
            send_icmp_3(sr, 3, 3, packet, interface,len);
            return;
          }
      }else{
          printf("Received ip not for me, start processing..... \n");
          /*check rtable, perform longest prefix match*/
          struct sr_rt* result = LPM(sr->routing_table,ip_header->ip_dst);
          if(result){
            printf("LPM found \n");
            struct sr_if *out = sr_get_interface(sr, result->interface);
            ip_header->ip_ttl--;
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum(ip_header, sizeof(struct sr_ip_hdr));
            struct sr_arpentry * arpentry = sr_arpcache_lookup (&sr->cache, result->gw.s_addr);
            if(arpentry){
              memcpy(e_header->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
              memcpy(e_header->ether_shost, out->addr, ETHER_ADDR_LEN);
              int re = sr_send_packet(sr, (uint8_t*) packet, len, out->name);
              if (re!=0) {
                printf("Forwarded IP Failed\n");
              }

            }else{

              struct sr_arpreq * req = sr_arpcache_queuereq(&sr->cache,ip_header->ip_dst, packet,len,out->name);
              handle_arpreq(sr, req);
            }

          }else{
            printf("LPM not found \n");
            ip_header->ip_ttl--;
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum(ip_header, sizeof(struct sr_ip_hdr));

            send_icmp_3(sr, 3, 0, packet, interface, len);
          }
      }

}

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

    printf("*** -> Received packet of length %d \n",len);

    /* fill in code here */
    print_hdrs(packet,len);
    /*First decide which type it is*/
    uint16_t type = ethertype(packet);
    printf("Type is : %d\n", type);
    if (type == ethertype_arp){
      printf("ARP handleing.......\n");
      sr_handlearp(sr,packet,len,interface);
    }else if (type == ethertype_ip){
      printf("IP handleing.......\n");
      sr_handleip(sr,packet,len,interface);
    }else{
      printf("Type is unkown.");
    }
}/* end sr_ForwardPacket */
