# cpp-pcap
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
