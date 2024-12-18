#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

struct ethheader {
  u_char  ether_dhost[6];		/* destination host address */
  u_char  ether_shost[6];		/* source host address */
  u_short ether_type;			/* IP? ARP? RARP? etc */
};



struct ipheader {
  unsigned char      iph_ihl:4,		// IP header length
                     iph_ver:4; 	// IP version
  unsigned char      iph_tos; 		// Type of service
  unsigned short int iph_len; 		// IP Packet length (data + header)
  unsigned short int iph_ident; 	// Identification
  unsigned short int iph_flag:3, 	// Fragmentation flags
                     iph_offset:13; 	// Flags offset
  unsigned char      iph_ttl; 		// Time to Live
  unsigned char      iph_protocol; 	// Protocol type
  unsigned short int iph_chksum; 	// IP datagram checksum
  struct  in_addr    iph_sourceip; 	// Source IP address 
  struct  in_addr    iph_destip;   	// Destination IP address 
};



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ethheader* eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    printf("\n*********Sniffed a Packet*********\n");
    printf("Source: %s ", inet_ntoa(ip->iph_sourceip));
    printf("Destination: %s\n", inet_ntoa(ip->iph_destip));
  }
}


int main() {

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "ip proto icmp";
	bpf_u_int32 net;

	// step 1: open live pcap session on NIC with interface name
	handle = pcap_open_live("br-49ad3adbe800", BUFSIZ, 1, 1000, errbuf);

	// step 2: compile filter_exp into BPF pseudo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	// step 3: capture packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle); // close the handle
	
	return 0;
}
