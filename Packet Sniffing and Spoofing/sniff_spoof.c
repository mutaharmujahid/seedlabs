#include <pcap.h>  // pcap library for packet capture
#include <stdio.h>  // standard input/output library
#include <stdlib.h> // standard library for memory allocation and exit
#include <sys/socket.h>  // socket programming library
#include <string.h>  // string manipulation library
#include <arpa/inet.h>  // library for IP address manipulation
#include <netinet/ip.h>  // IP protocol header
#include <unistd.h>  // POSIX library for system calls

// Structure for Ethernet header
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* Type of the protocol (e.g., IP, ARP) */
};

// Structure for IP header
struct ipheader {
  unsigned char      iph_ihl:4, // IP header length
                     iph_ver:4; // IP version
  unsigned char      iph_tos; // Type of service
  unsigned short int iph_len; // Length of the IP packet (header + data)
  unsigned short int iph_ident; // Identification field for fragmentation
  unsigned short int iph_flag:3, // Fragmentation flags
                     iph_offset:13; // Fragment offset
  unsigned char      iph_ttl; // Time to Live (TTL) field
  unsigned char      iph_protocol; // Protocol type (e.g., ICMP, TCP, UDP)
  unsigned short int iph_chksum; // Checksum for the IP header
  struct  in_addr    iph_sourceip; // Source IP address
  struct  in_addr    iph_destip;   // Destination IP address
};

// Structure for ICMP header
struct icmpheader {
  unsigned char icmp_type; // ICMP message type (e.g., Echo Request, Echo Reply)
  unsigned char icmp_code; // Error code for ICMP (specific to message type)
  unsigned short int icmp_chksum; // Checksum for ICMP header and data
  unsigned short int icmp_id;     // Used for identifying request/reply pairs
  unsigned short int icmp_seq;    // Sequence number for the ICMP message
};

// Function to calculate checksum for data (used in both IP and ICMP headers)
unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp = 0;

   // Accumulate sum of 16-bit words
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   // If there is an odd byte, process it
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
   }

   // Fold back any carry bits and return the result
   sum = (sum >> 16) + (sum & 0xffff);  // Add the carry bits
   sum += (sum >> 16);                  // Add the carry bits again
   return (unsigned short)(~sum);       // Return the 16-bit one's complement
}

// Function to send a raw IP packet
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Create a raw socket for IP packets
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Set socket option to include the IP header
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Set the destination IP address for the packet
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Send the raw IP packet
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));

    // Close the socket after sending the packet
    close(sock);
}

// Callback function to handle received packets
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  // Parse the Ethernet header from the packet
  struct ethheader* eth = (struct ethheader *)packet;

  // Check if the packet contains an IP packet (Ethernet type 0x0800)
  if (ntohs(eth->ether_type) == 0x0800) {
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    int size_ip = ip->iph_ihl * 4;  // Calculate IP header size

    // Check if the packet is an ICMP packet
    if (ip->iph_protocol == IPPROTO_ICMP){
      printf("\n\n====Captured ICMP Packet====\n");
      printf("Source: %s\n", inet_ntoa(ip->iph_sourceip));  // Print source IP address
      printf("Destination: %s\n\n", inet_ntoa(ip->iph_destip));  // Print destination IP address

      // Extract the ICMP header and check if it's an Echo Request (Type 8)
      struct icmpheader* icmpData = (struct icmpheader*)((u_char *)packet + sizeof(struct ethheader) + size_ip);
      if (icmpData->icmp_type == 8) {  // Type 8 is Echo Request
        char buffer[1500];
        int data_len = header->len - (sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct icmpheader));
        char *data = (char *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct icmpheader));

        // Copy the data from the original ICMP packet into the buffer
        memcpy(buffer + sizeof(struct ipheader) + sizeof(struct icmpheader), data, data_len);

        // Prepare the IP header for the reply
        struct ipheader *ip2 = (struct ipheader *) buffer;
        ip2->iph_ver = 4;
        ip2->iph_ihl = 5;
        ip2->iph_ttl = 20;  // Set a TTL for the reply packet
        ip2->iph_sourceip = ip->iph_destip;  // Source IP of the reply is the original destination
        ip2->iph_destip = ip->iph_sourceip;  // Destination IP of the reply is the original source
        ip2->iph_protocol = IPPROTO_ICMP;  // Set protocol to ICMP
        ip2->iph_chksum = 0;  // Initialize checksum to 0
        ip2->iph_chksum = in_cksum((unsigned short *)ip2, sizeof(struct ipheader));  // Compute checksum
        ip2->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader) + data_len);  // Set total packet length

        // Prepare the ICMP header for the reply
        struct icmpheader *icmp = (struct icmpheader *)(buffer + (ip->iph_ihl * 4));
        icmp->icmp_type = 0;  // Type 0 is Echo Reply
        icmp->icmp_code = icmpData->icmp_code;
        icmp->icmp_id = icmpData->icmp_id;
        icmp->icmp_seq = icmpData->icmp_seq;

        // Calculate the ICMP checksum
        icmp->icmp_chksum = 0;
        icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader) + data_len);

        // Send the crafted ICMP Echo Reply packet
        send_raw_ip_packet(ip2);
        printf("====Sent Spoof ICMP====");
      }
    }
  }
}

// Main function
int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "proto ICMP";  // Filter to capture only ICMP packets
  bpf_u_int32 net;

  // Step 1: Open a live pcap session on the specified network interface
  handle = pcap_open_live("br-427d7efc0bbb", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile the BPF filter expression for ICMP protocol
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Start capturing packets and call got_packet for each captured packet
  pcap_loop(handle, -1, got_packet, NULL);

  // Close the pcap handle after packet capture is complete
  pcap_close(handle); 
  
  return 0;
}

