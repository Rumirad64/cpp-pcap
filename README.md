# cpp-pcap

## pcap_open_live() - Open a live capture

```cpp
pcap_t *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf)

```
**Parameters:**

- **device**: A string that specifies the name of the network interface to open.
- **snaplen**: The maximum number of bytes to capture per packet.
- **promisc**: Specifies whether to capture packets in promiscuous mode. A value of 0 disables promiscuous mode, while a non-zero value enables it.
- **to_ms**: The read timeout in milliseconds. A value of 0 means no timeout.
- **errbuf**: A pointer to a buffer that will hold any error messages.


**Return value:**

- A pointer to a pcap_t structure, which is the handle for the opened capture session.
A NULL pointer if the capture session could not be opened, in which case errbuf will contain a description of the error.

**Description:**
- **pcap_open_live** is a function in the PCAP library that is used to open a network interface for packet capture. The function takes as input the name of the network interface to be opened, the maximum number of bytes to capture per packet, and the read timeout. The function returns a handle to the opened capture session, which can be used to capture packets and process them as desired.

- The **device** parameter should specify the name of the network interface to be opened. This name can be obtained using the **pcap_lookupdev** function.

- The **snaplen** parameter specifies the maximum number of bytes to capture per packet. Packets that are larger than **snaplen** will be truncated to this length.

- The **promisc** parameter specifies whether to capture packets in promiscuous mode. In promiscuous mode, the network interface captures all packets that are transmitted or received on the network, regardless of whether they are intended for the host or not. A value of 0 disables promiscuous mode, while a non-zero value enables it.

- The **to_ms** parameter specifies the read timeout in milliseconds. This timeout is used to specify the amount of time that the capture session should wait for a packet to arrive before returning. A value of 0 means that there is no timeout, and the capture session will wait indefinitely for a packet to arrive.

- The **errbuf** parameter is a pointer to a buffer that will hold any error messages that occur during the capture session. The size of the buffer should be at least PCAP_ERRBUF_SIZE bytes, as specified in the **PCAP** library documentation.

- The return value is a pointer to a **pcap_t** structure, which is the handle for the opened capture session. If the capture session could not be opened, the function returns a **NULL** pointer, and the **errbuf** parameter will contain a description of the error.


To create a Docker network with a specific subnet and plug the host PC into it, you can use the following steps:

Create the network:

docker network create --subnet=192.168.100.0/24 mynetwork

Connect the host to the network:

docker network connect mynetwork ['eth0']

Where [host_interface_name] is the name of the host's network interface, for example "eth0" or "wlan0".

Start a container and connect it to the network:

docker run --network=mynetwork --name mycontainer -it myimage

Note: This is a basic example and the exact steps may vary based on your setup, you may need to consult the Docker documentation for more information.

docker run --network="bridge" --name my-running-app -it my-cplusplus-app

https://pubs.opengroup.org/onlinepubs/009695399/basedefs/netinet/in.h.html
