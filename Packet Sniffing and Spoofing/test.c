#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>

// Pseudo header needed for TCP checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// IP Header structure
struct ipheader {
    unsigned char iph_ihl : 4, iph_ver : 4; // IP header length and version
    unsigned char iph_tos;                   // Type of service
    unsigned short iph_len;                  // Total length
    unsigned short iph_ident;                // Identification
    unsigned short iph_flag : 3, iph_offset : 13; // Flags and fragment offset
    unsigned char iph_ttl;                   // Time to live
    unsigned char iph_protocol;              // Protocol (TCP, UDP, ICMP)
    unsigned short iph_chksum;               // Checksum
    struct in_addr iph_sourceip;             // Source IP address
    struct in_addr iph_destip;               // Destination IP address
};

// TCP Header structure
struct tcpheader {
    unsigned short tcph_srcport;
    unsigned short tcph_destport;
    unsigned int tcph_seqnum;
    unsigned int tcph_acknum;
    unsigned char tcph_reserved : 4, tcph_offset : 4;
    unsigned char tcph_flags;
    unsigned short tcph_win;
    unsigned short tcph_chksum;
    unsigned short tcph_urgptr;
};

// Calculate the checksum for the packet headers
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main() {
    int sd;
    struct sockaddr_in sin;
    char buffer[1024];

    struct ipheader *iph = (struct ipheader *) buffer;
    struct tcpheader *tcph = (struct tcpheader *) (buffer + sizeof(struct ipheader));
    struct pseudo_header psh;

    // Create a raw socket with IPPROTO_RAW to avoid OS adding IP header
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("Socket creation failed");
        exit(-1);
    }

    // Destination details
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80); // Target port (HTTP)
    sin.sin_addr.s_addr = inet_addr("10.9.0.6"); // Target IP address (spoofed destination)

    // Construct the IP header
    iph->iph_ver = 4;
    iph->iph_ihl = 5;  // Header length (5 words, 20 bytes)
    iph->iph_tos = 0;  // Type of service
    iph->iph_len = sizeof(struct ipheader) + sizeof(struct tcpheader); // Total packet size
    iph->iph_ident = htons(54321);  // Identifier
    iph->iph_flag = 0;
    iph->iph_offset = 0;
    iph->iph_ttl = 255;  // TTL
    iph->iph_protocol = IPPROTO_TCP;  // Protocol (TCP)
    iph->iph_chksum = 0;  // Initially set to 0 for checksum calculation
    iph->iph_sourceip.s_addr = inet_addr("10.9.0.5");  // Spoofed source IP
    iph->iph_destip.s_addr = sin.sin_addr.s_addr;  // Target destination IP

    // IP checksum
    iph->iph_chksum = checksum((unsigned short *)buffer, iph->iph_len);

    // Construct the TCP header
    tcph->tcph_srcport = htons(12345);  // Source port (random)
    tcph->tcph_destport = htons(80);    // Destination port (HTTP)
    tcph->tcph_seqnum = 0;
    tcph->tcph_acknum = 0;
    tcph->tcph_reserved = 0;
    tcph->tcph_offset = 5;  // Data offset (5 words, 20 bytes)
    tcph->tcph_flags = 0x02;  // SYN flag
    tcph->tcph_win = htons(5840);  // Window size
    tcph->tcph_chksum = 0;  // Initially set to 0 for checksum calculation
    tcph->tcph_urgptr = 0;

    // Pseudo header needed for checksum calculation
    psh.source_address = inet_addr("10.9.0.5");  // Spoofed source IP
    psh.dest_address = sin.sin_addr.s_addr;  // Target IP
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;  // TCP protocol
    psh.tcp_length = htons(sizeof(struct tcpheader));

    // Allocate space for the pseudo header and TCP header
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcpheader);
    char *pseudogram = malloc(psize);

    // Copy pseudo header and TCP header into the pseudogram
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcpheader));

    // TCP checksum
    tcph->tcph_chksum = checksum((unsigned short *)pseudogram, psize);

    // Send the packet
    if (sendto(sd, buffer, iph->iph_len + sizeof(struct tcpheader), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("Send failed");
        exit(-1);
    }

    printf("Spoofed packet sent!\n");

    // Close the socket
    close(sd);

    return 0;
}
