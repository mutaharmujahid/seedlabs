#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>



struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};



struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};


struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};





unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}
  
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, 
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0, 
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader* eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        int size_ip = ip->iph_ihl * 4;

        printf("\n=========================== New Packet ===========================\n");

        // Process only ICMP packets
        if (ip->iph_protocol == IPPROTO_ICMP) {
            struct icmpheader *icmpData = (struct icmpheader *)((u_char *)packet + sizeof(struct ethheader) + size_ip);

            // Only respond if it's an ICMP Echo Request (type 8)
            if (icmpData->icmp_type == 8) {
                int data_len = header->len - (sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct icmpheader));
                char *data = (char *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct icmpheader));
                char buffer[1500];
                memset(buffer, 0, 1500);
                memcpy(buffer + sizeof(struct ipheader) + sizeof(struct icmpheader), data, data_len);

                // Prepare the new IP header for the reply
                struct ipheader *ip2 = (struct ipheader *)buffer;
                ip2->iph_ver = 4;
                ip2->iph_ihl = 5;
                ip2->iph_ttl = 20;
                ip2->iph_sourceip = ip->iph_destip;
                ip2->iph_destip = ip->iph_sourceip;
                ip2->iph_protocol = IPPROTO_ICMP;
                ip2->iph_chksum = 0;
                ip2->iph_chksum = in_cksum((unsigned short *)ip2, sizeof(struct ipheader));
                ip2->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader) + data_len);

                // Build ICMP Header for the reply
                struct icmpheader *icmp = (struct icmpheader *)(buffer + (ip->iph_ihl * 4));
                icmp->icmp_type = 0;  // ICMP Type: 0 is reply
                icmp->icmp_code = icmpData->icmp_code;
                icmp->icmp_id = icmpData->icmp_id;
                icmp->icmp_seq = icmpData->icmp_seq;

                // Calculate the checksum
                icmp->icmp_chksum = 0;
                icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader) + data_len);

                // **Block the reply here**: Do not send the packet, effectively blocking the reply from reaching the sender.
                // send_raw_ip_packet(ip2); // Comment or remove this line to block the reply

                printf("\n==================== ICMP Reply Blocked ====================\n");
                printf("  ICMP Reply Blocked to: %s\n", inet_ntoa(ip2->iph_destip));
                printf("  Source IP: %s, Destination IP: %s\n", inet_ntoa(ip2->iph_sourceip), inet_ntoa(ip2->iph_destip));
                printf("  Type: %d (Reply), Code: %d\n", icmp->icmp_type, icmp->icmp_code);
                printf("  ID: %d, Sequence: %d\n", ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
            }
        }
    }
}



int main() {

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "proto ICMP";
	bpf_u_int32 net;

	// step 1: open live pcap session on NIC with interface name
	handle = pcap_open_live("br-427d7efc0bbb", BUFSIZ, 1, 1000, errbuf);

	// step 2: compile filter_exp into BPF pseudo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	// step 3: capture packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle); // close the handle
	
	return 0;
}
