#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>

int main()
{
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0)
  {
    std::cerr << "Error creating socket" << std::endl;
    return 1;
  }

  // Allow sending of IP packets
  int on = 1;
  if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
  {
    std::cerr << "Error setting socket option" << std::endl;
    return 1;
  }

  // Destination address
  struct sockaddr_in dest_addr;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  // IP header
  struct iphdr header;
  header.version = 4;
  header.ihl = 5;
  header.tos = 0;
  header.tot_len = htons(sizeof(header) + sizeof(dest_addr) + strlen("Hello, World!"));
  header.id = htons(0);
  header.frag_off = 0;
  header.ttl = 64;
  header.protocol = IPPROTO_UDP;
  header.check = 0;
  header.saddr = inet_addr("127.0.0.1");
  header.daddr = dest_addr.sin_addr.s_addr;

  // Message to be sent
  char *message = "Hello, World!";

  // Send the message
  int bytes_sent = sendto(sock, &header, sizeof(header), 0,
                          (struct sockaddr *)&dest_addr, sizeof(dest_addr));
  if (bytes_sent < 0)
  {
    std::cerr << "Error sending header" << std::endl;
    return 1;
  }

  bytes_sent = sendto(sock, message, strlen(message), 0,
                      (struct sockaddr *)&dest_addr, sizeof(dest_addr));
  if (bytes_sent < 0)
  {
    std::cerr << "Error sending message" << std::endl;
    return 1;
  }

  std::cout << "Sent " << bytes_sent << " bytes." << std::endl;
  return 0;
}
