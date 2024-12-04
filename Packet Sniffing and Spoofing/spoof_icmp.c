#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>

// IP Header structure
struct ipheader {
    unsigned char ip_ihl : 4, ip_ver : 4; // IP header length and version
    unsigned char ip_tos;                 // Type of service
    unsigned short ip_len;                // Total length
    unsigned short ip_ident;              // Identification
    unsigned short ip_flag : 3, ip_offset : 13; // Flags and fragment offset
    unsigned char ip_ttl;                 // Time to live
    unsigned char ip_protocol;            // Protocol (TCP, UDP, ICMP)
    unsigned short ip_chksum;             // Checksum
    struct in_addr ip_sourceip;           // Source IP address
    struct in_addr ip_destip;             // Destination IP address
};

// ICMP Header structure
struct icmpheader {
    unsigned char icmp_type;    // ICMP message type
    unsigned char icmp_code;    // Error code
    unsigned short int icmp_chksum; // Checksum
    unsigned short int icmp_id;     // Identification
    unsigned short int icmp_seq;    // Sequence number
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

    memset(buffer, 0, 1024); // Clear the buffer

    // Create a raw socket
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("Socket creation failed");
        exit(-1);
    }

    struct ipheader *ip = (struct ipheader *)buffer;
    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));

    // Construct the ICMP header
    icmp->icmp_type = 8; // ICMP Echo Request
    icmp->icmp_code = 0;
    icmp->icmp_id = htons(1);    // Identification
    icmp->icmp_seq = htons(1);   // Sequence number
    icmp->icmp_chksum = 0;       // Initialize to 0 for checksum calculation

    // Calculate ICMP checksum
    icmp->icmp_chksum = checksum((unsigned short *)icmp, sizeof(struct icmpheader));

    // Construct the IP header
    ip->ip_ver = 4;                  // IPv4
    ip->ip_ihl = 5;                  // Header length (5 words, 20 bytes)
    ip->ip_tos = 0;                  // Type of service
    ip->ip_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader)); // Total packet size
    ip->ip_ident = htons(54321);     // Identification
    ip->ip_flag = 0;                 // Flags
    ip->ip_offset = 0;               // Fragment offset
    ip->ip_ttl = 64;                 // Time-to-live
    ip->ip_protocol = IPPROTO_ICMP;  // Protocol (ICMP)
    ip->ip_chksum = 0;               // Initialize to 0 for checksum calculation
    ip->ip_sourceip.s_addr = inet_addr("10.9.0.5");
	  ip->ip_destip.s_addr = inet_addr("8.8.8.8");
    
    
    sin.sin_family = AF_INET;
	  sin.sin_addr = ip->ip_destip;

    // Calculate IP checksum
    ip->ip_chksum = checksum((unsigned short *)ip, sizeof(struct ipheader));

    // Send the packet
    if (sendto(sd, buffer, ntohs(ip->ip_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("Send failed");
        exit(-1);
    }

    printf("Spoofed ICMP Echo Request sent!\n");

    // Close the socket
    close(sd);

    return 0;
}

