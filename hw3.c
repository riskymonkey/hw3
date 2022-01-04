#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#define MAC_ADDRSTRLEN 2*6+5+1
#define BUFSIZE 65535

char *mac_ntoa(u_char *d) {
    static char str[MAC_ADDRSTRLEN];
    snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
    return str;
}

char *ip_ntoa(void *i) {
    static char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, i, str, sizeof(str));
    return str;
}

void tcp_handler(const u_char *packet){
    struct ip *ip = (struct ip *)(packet + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip->ip_hl * 4));
    u_int16_t source_port = ntohs(tcp -> th_sport);
    u_int16_t destination_port = ntohs(tcp -> th_dport);
    printf("TCP:\n");
    printf("Source Port: %u\n", source_port);
    printf("Destination Port: %u\n", destination_port);
    printf("\n");
}

void udp_handler(const u_char *packet){
    struct ip *ip = (struct ip *)(packet + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(packet + ETHER_HDR_LEN + (ip->ip_hl * 4));
    u_int16_t source_port = ntohs(udp -> uh_sport);
    u_int16_t destination_port = ntohs(udp -> uh_dport);
    printf("UDP:\n");
    printf("Source Port: %u\n", source_port);
    printf("Destination Port: %u\n", destination_port);
    printf("\n");
}

void ip_handler(u_int32_t length, const u_char *packet){
    struct ip *ip = (struct ip *)(packet + ETHER_HDR_LEN);
    printf("This is IP packet\n");
    printf("Source IP Address: %s\n",  ip_ntoa(&ip->ip_src));
    printf("Destination IP Address: %s\n", ip_ntoa(&ip->ip_dst));
    u_char protocal = ip -> ip_p;
    switch(protocal){
        case IPPROTO_UDP:
            udp_handler(packet);
            break;
        case IPPROTO_TCP:
            tcp_handler(packet);
            break;
        default:
            printf("This is other protocal\n");
            break;
    }
}

void my_handler(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    int *id = (int *)arg;
    printf("id: %d\n", ++(*id));
    printf("Recieved time: %s", ctime((const time_t *)&pkthdr -> ts.tv_sec));
    printf("Total length: %d bytes\n", pkthdr -> len);
    printf("Capture length: %d bytes\n", pkthdr -> caplen);

    struct ether_header *eth_header;
    eth_header = (struct ether_header *)packet;

    /*if (ntohs(eth_header -> ether_type) == ETHERTYPE_IP) {
        printf("It is an IP packet.\n"); 
    }
    else if(ntohs(eth_header -> ether_type) == ETHERTYPE_ARP){
        printf("It is an ARP packet.\n"); 
    }*/
    char dst_mac[MAC_ADDRSTRLEN] = {0};
    char src_mac[MAC_ADDRSTRLEN] = {0};
    struct ether_header *ethernet = (struct ether_header *)packet;
    strncpy(dst_mac, mac_ntoa(ethernet->ether_dhost), sizeof(dst_mac));
    strncpy(src_mac, mac_ntoa(ethernet->ether_shost), sizeof(src_mac));
    u_int16_t type = ntohs(ethernet -> ether_type);

    printf("\n");
    printf("dst mac address: %s\n", dst_mac);
    printf("src mac address: %s\n", src_mac);
    printf("\n");

    /*if (type < 1500) printf("| Length: %5u|\n", type);
    else printf("| Ethernet Type: 0x%04x |\n", type);*/

    printf("Next protocol is ");
    switch (type) {
        case ETHERTYPE_ARP:
            printf("ARP\n");
            break;
        
        case ETHERTYPE_IP:
            printf("IP\n");
            ip_handler(pkthdr -> caplen, packet);
            break;
        
        case ETHERTYPE_REVARP:
            printf("RARP\n");
            break;
        
        case ETHERTYPE_IPV6:
            printf("IPv6\n");
            break;
        
        default:
            printf("other: ");
            printf("%#06x\n", type);
            break;
    }
    
}

int main(int argc, char **argv){
    char errbuf[PCAP_ERRBUF_SIZE], *dev;
    char filename[1024];
    //無限循環
    int cnt = -1, in = 0;
    pcap_t *handle = NULL;
    
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        exit(-1);
    }else printf("find success\n");

    handle = pcap_open_live(dev, BUFSIZE, 1, 0, errbuf);
    if (handle == NULL) {
	    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
	    exit(-1);
    }else printf("open success\n");

    if(argc == 3){
        if(strcmp(argv[1], "-r") == 0){
            strcpy(filename, argv[2]);
            handle = pcap_open_offline(filename, errbuf);
            if(!handle){
                fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
                exit(1);
            }else printf("open: %s\n", filename);
        }
    }

    pcap_loop(handle, cnt, my_handler, (u_char *)&in);
    pcap_close(handle);

    return 0;
}