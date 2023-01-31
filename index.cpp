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
#include <cstdlib>

const string FILENAME = "data.txt";
std::ofstream file;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
  struct ip *ip_hdr = (struct ip *)(pkt_data + 14);
  in_addr src_ip, dst_ip;
  src_ip = ip_hdr->ip_src;
  dst_ip = ip_hdr->ip_dst;

  std::cout << "Packet captured:" << std::endl;
  std::cout << "  Source IP: " << inet_ntoa(src_ip) << std::endl;
  std::cout << "  Destination IP: " << inet_ntoa(dst_ip) << std::endl;

  /* check the protocol type */
  if (ip_hdr->ip_p == IPPROTO_TCP)
  {
    /* handle TCP packet */
    struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_data + 14 + (ip_hdr->ip_hl * 4));
    u_short src_port = tcp_hdr->th_sport;
    u_short dst_port = tcp_hdr->th_dport;

    std::cout << "  Protocol: TCP" << std::endl;
    std::cout << "  Source Port: " << ntohs(src_port) << std::endl;
    std::cout << "  Destination Port: " << ntohs(dst_port) << std::endl;
    file << "TCP"
         << " \tSource IP: " << inet_ntoa(src_ip) << " \t\t\t\t\t\tDestination IP: " << inet_ntoa(dst_ip) << " \t\t\t Source Port: " << ntohs(src_port) << " \t\t\t\t Destination Port: " << ntohs(dst_port) << std::endl;
  }
  else if (ip_hdr->ip_p == IPPROTO_ICMP)
  {
    /* handle ICMP packet */
    struct icmphdr *icmp_hdr = (struct icmphdr *)(pkt_data + 14 + (ip_hdr->ip_hl * 4));
    std::cout << "  Protocol: ICMP" << std::endl;
    std::cout << "  ICMP Type: " << (int)icmp_hdr->type << std::endl;
    std::cout << "  ICMP Code: " << (int)icmp_hdr->code << std::endl;
  }
  else if (ip_hdr->ip_p == IPPROTO_UDP)
  {
    /* handle UDP packet */
    struct udphdr *udp_hdr = (struct udphdr *)(pkt_data + 14 + (ip_hdr->ip_hl * 4));
    u_short src_port = udp_hdr->uh_sport;
    u_short dst_port = udp_hdr->uh_dport;

    std::cout << "  Protocol: UDP" << std::endl;
    std::cout << "  Source Port: " << ntohs(src_port) << std::endl;
    std::cout << "  Destination Port: " << ntohs(dst_port) << std::endl;
    file << "UDP"
         << " \tSource IP: " << inet_ntoa(src_ip) << " \t\t\t\t\t\tDestination IP: " << inet_ntoa(dst_ip) << " \t\t\t Source Port: " << ntohs(src_port) << " \t\t\t\t Destination Port: " << ntohs(dst_port) << std::endl;
  }
  if (ip_hdr->ip_p == IPPROTO_IP)
  {
    /* handle IP packet */
    std::cout << "  Protocol: IP" << std::endl;
    std::cout << "  Source IP: " << inet_ntoa(src_ip) << std::endl;
    std::cout << "  Destination IP: " << inet_ntoa(dst_ip) << std::endl;
    std::cout << "  Total Length: " << ntohs(ip_hdr->ip_len) << " bytes" << std::endl;
    std::cout << "  TTL: " << (int)ip_hdr->ip_ttl << std::endl;
    std::cout << "  Protocol: " << (int)ip_hdr->ip_p << std::endl;
    std::cout << "  Checksum: 0x" << std::hex << ntohs(ip_hdr->ip_sum) << std::endl;
  }
  else
  {
    /* handle other protocols */
    std::cout << "  Protocol: " << (int)ip_hdr->ip_p << std::endl;
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
void listAdapters()
{
  char errorBuffer[PCAP_ERRBUF_SIZE];
  pcap_if_t *interfaces, *currentInterface;

  // Get the list of available adapters
  if (pcap_findalldevs(&interfaces, errorBuffer) == -1)
  {
    std::cerr << "Error getting adapter list: " << errorBuffer << std::endl;
    return;
  }

  // Dump information for each adapter to the console
  for (currentInterface = interfaces; currentInterface != nullptr; currentInterface = currentInterface->next)
  {
    std::cout << "Adapter: " << currentInterface->name << std::endl;

    if (currentInterface->description)
    {
      std::cout << "Description: " << currentInterface->description << std::endl;
    }

    std::cout << "Addresses: " << std::endl;
    pcap_addr_t *currentAddress;
    for (currentAddress = currentInterface->addresses; currentAddress != nullptr; currentAddress = currentAddress->next)
    {
      std::cout << "\tAddress Family: " << currentAddress->addr->sa_family << std::endl;

      if (currentAddress->addr->sa_family == AF_INET)
      {
        std::cout << "\tAddress: " << inet_ntoa(((struct sockaddr_in *)currentAddress->addr)->sin_addr) << std::endl;
      }
      else if (currentAddress->addr->sa_family == AF_INET6)
      {
        char addressBuffer[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)currentAddress->addr)->sin6_addr), addressBuffer, INET6_ADDRSTRLEN);
        std::cout << "\tAddress: " << addressBuffer << std::endl;
      }
    }

    std::cout << std::endl;
  }

  // Free the adapter list
  pcap_freealldevs(interfaces);
}

int main(int argc, char *argv[])
{
  file.open(FILENAME, std::ios::app); // open the file in append mode

  // run listAdapters() ifconfig and print the output
  listAdapters();

  char *dev, errbuf[PCAP_ERRBUF_SIZE];

  /* get the first available device */
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL)
  {
    std::cerr << "Couldn't find default device: " << errbuf << std::endl;
    return 1;
  }

  /* open the device for capturing */
  pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 10, errbuf);
  if (handle == NULL)
  {
    std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
    return 2;
  }

  /* start capturing packets */
  if (pcap_loop(handle, -1, packet_handler, NULL) < 0)
  {
    std::cerr << "pcap_loop exited with error" << std::endl;
    return 3;
  }

  pcap_close(handle);
  return 0;
}
