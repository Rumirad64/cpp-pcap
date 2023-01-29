#include <iostream>
using namespace std;

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <fstream>
#include <string>

const string FILENAME = "data.txt";
std::ofstream file;


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  struct ip *ip_hdr = (struct ip *)(pkt_data + 14);
  in_addr src_ip, dst_ip;
  src_ip = ip_hdr->ip_src;
  dst_ip = ip_hdr->ip_dst;

  std::cout << "Packet captured:" << std::endl;
  std::cout << "  Source IP: " << inet_ntoa(src_ip) << std::endl;
  std::cout << "  Destination IP: " << inet_ntoa(dst_ip) << std::endl;

  /* check the protocol type */
  if (ip_hdr->ip_p == IPPROTO_TCP) {
    /* handle TCP packet */
    struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_data + 14 + (ip_hdr->ip_hl * 4));
    u_short src_port = tcp_hdr->th_sport;
    u_short dst_port = tcp_hdr->th_dport;

    std::cout << "  Protocol: TCP" << std::endl;
    std::cout << "  Source Port: " << ntohs(src_port) << std::endl;
    std::cout << "  Destination Port: " << ntohs(dst_port) << std::endl;
    file << "TCP" << " \tSource IP: " << inet_ntoa(src_ip) << " \t\t\t\t\t\tDestination IP: " << inet_ntoa(dst_ip) << " \t\t\t Source Port: " << ntohs(src_port) << " \t\t\t\t Destination Port: " << ntohs(dst_port) << std::endl;
  } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
    /* handle ICMP packet */
    struct icmphdr *icmp_hdr = (struct icmphdr *)(pkt_data + 14 + (ip_hdr->ip_hl * 4));
    std::cout << "  Protocol: ICMP" << std::endl;
    std::cout << "  ICMP Type: " << (int)icmp_hdr->type << std::endl;
    std::cout << "  ICMP Code: " << (int)icmp_hdr->code << std::endl;
  } 
  else if (ip_hdr->ip_p == IPPROTO_UDP) {
    /* handle UDP packet */
    struct udphdr *udp_hdr = (struct udphdr *)(pkt_data + 14 + (ip_hdr->ip_hl * 4));
    u_short src_port = udp_hdr->uh_sport;
    u_short dst_port = udp_hdr->uh_dport;

    std::cout << "  Protocol: UDP" << std::endl;
    std::cout << "  Source Port: " << ntohs(src_port) << std::endl;
    std::cout << "  Destination Port: " << ntohs(dst_port) << std::endl;
    file << "UDP" << " \tSource IP: " << inet_ntoa(src_ip) << " \t\t\t\t\t\tDestination IP: " << inet_ntoa(dst_ip) << " \t\t\t Source Port: " << ntohs(src_port) << " \t\t\t\t Destination Port: " << ntohs(dst_port) << std::endl;

  }
  else {
    /* handle other protocols */
    std::cout << "  Protocol: Other" << std::endl;
  }
}

// base code

// void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
//   /* extract the source and destination IP addresses */
//   in_addr src_ip, dst_ip;
//   src_ip.s_addr = *(in_addr_t *)(pkt_data + 26);
//   dst_ip.s_addr = *(in_addr_t *)(pkt_data + 30);

//   /* extract the source and destination ports */
//   u_short src_port = *(u_short *)(pkt_data + 34);
//   u_short dst_port = *(u_short *)(pkt_data + 36);

//   /* print the extracted information */
//   // std::cout << "Packet captured:" << std::endl;
//   std::cout << "  Source IP: " << inet_ntoa(src_ip);
//   std::cout << "  Destination IP: " << inet_ntoa(dst_ip);
//   std::cout << "  Source Port: " << ntohs(src_port);
//   std::cout << "  Destination Port: " << ntohs(dst_port) << std::endl;
// }

int main(int argc, char *argv[]) {
  file.open(FILENAME, std::ios::app); // open the file in append mode

  char *dev, errbuf[PCAP_ERRBUF_SIZE];

  /* get the first available device */
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    std::cerr << "Couldn't find default device: " << errbuf << std::endl;
    return 1;
  }

  /* open the device for capturing */
  pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 10, errbuf);
  if (handle == NULL) {
    std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
    return 2;
  }

  /* start capturing packets */
  if (pcap_loop(handle, -1, packet_handler, NULL) < 0) {
    std::cerr << "pcap_loop exited with error" << std::endl;
    return 3;
  }

  pcap_close(handle);
  return 0;
}
