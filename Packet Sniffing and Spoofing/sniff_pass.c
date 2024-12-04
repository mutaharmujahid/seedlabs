#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <arpa/inet.h>

// Ethernet header structure
struct ethheader {
    u_char ether_dhost[6]; // Destination MAC
    u_char ether_shost[6]; // Source MAC
    u_short ether_type;    // Ethernet type (e.g., IP)
};

// IP header structure
struct ipheader {
    unsigned char iph_ihl : 4, // IP header length
                  iph_ver : 4; // IP version
    unsigned char iph_tos;     // Type of service
    unsigned short int iph_len; // IP packet length
    unsigned short int iph_ident; // Identification
    unsigned short int iph_flag : 3, // Fragmentation flags
                  iph_offset : 13;   // Fragmentation offset
    unsigned char iph_ttl;           // Time to Live
    unsigned char iph_protocol;      // Protocol type
    unsigned short int iph_chksum;   // Checksum
    struct in_addr iph_sourceip;     // Source IP
    struct in_addr iph_destip;       // Destination IP
};

// TCP header structure
struct tcpheader {
    unsigned short int tcph_srcport; // Source port
    unsigned short int tcph_destport; // Destination port
    unsigned int tcph_seqnum;         // Sequence number
    unsigned int tcph_acknum;         // Acknowledgment number
    unsigned char tcph_reserved : 4,  // Reserved bits
                  tcph_offset : 4;    // Data offset
    unsigned char tcph_flags;         // TCP flags
    unsigned short int tcph_win;      // Window size
    unsigned short int tcph_chksum;   // Checksum
    unsigned short int tcph_urgptr;   // Urgent pointer
};

// Function to process captured packets
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // Check if Ethernet frame contains an IP packet
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 = IP
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // Check if the IP packet contains a TCP segment
        if (ip->iph_protocol == IPPROTO_TCP) { // 6 = TCP
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
            int tcp_header_length = tcp->tcph_offset * 4;

            // Calculate payload offset and size
            const u_char *payload = packet + sizeof(struct ethheader) + (ip->iph_ihl * 4) + tcp_header_length;
            int payload_size = ntohs(ip->iph_len) - (ip->iph_ihl * 4) - tcp_header_length;

            // Only process packets with payload
            if (payload_size > 0) {
                // Check if the TCP segment is for Telnet (port 23)
                if (ntohs(tcp->tcph_srcport) == 23 || ntohs(tcp->tcph_destport) == 23) {
                    printf("\n********* Telnet Packet with Payload *********\n");
                    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
                    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
                    printf("Source Port: %d\n", ntohs(tcp->tcph_srcport));
                    printf("Destination Port: %d\n", ntohs(tcp->tcph_destport));
                    printf("Payload (%d bytes):\n", payload_size);

                    for (int i = 0; i < payload_size; i++) {
                        printf("%c", isprint(payload[i]) ? payload[i] : '.');
                    }
                    printf("\n");
                }
            }
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp port 23"; // Filter for Telnet traffic
    bpf_u_int32 net;

    // Step 1: Open live pcap session on the specified NIC
    handle = pcap_open_live("br-49ad3adbe800", BUFSIZ, 1, 1000, errbuf);

    // compile filter_Exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    // Cleanup
    pcap_close(handle);
    return 0;
}

