<img width="523" alt="NameSpacesNet" src="https://github.com/MdAhosanHabib/LinuxNetworkingNamespace/assets/43145662/3cc0a3fa-ae79-4af8-84ce-f8e1c8a0ed4d">

Introduction: This document outlines the steps involved in creating three network namespaces and demonstrates how to analyze packet traffic using Python.

Creating Namespaces: The first step is to create three network namespaces using the ip netns add command. These namespaces act as isolated network environments, allowing us to configure IP addresses and routing tables independently.

Creating the Bridge Interface: Next, a bridge interface is created using the ip link add command. The bridge interface serves as a connection point for the namespaces and allows them to communicate with each other and the host.

Creating Veth Pairs: Veth pairs are created using the ip link add command, with each pair consisting of an "inside" and an "outside" interface. These pairs serve as virtual Ethernet cables, connecting the namespaces to the bridge interface.

Adding Interfaces to the Bridge: The "outside" interfaces of the veth pairs are added to the bridge interface using the ip link set command. This step ensures that the namespaces can communicate with each other and the host through the bridge.

Adding Interfaces to the Namespaces: The "inside" interfaces of the veth pairs are added to their respective namespaces using the ip link set command. This step allows us to configure IP addresses and establish connectivity within each namespace.

Configuring IP Addresses: IP addresses are assigned to the "inside" interfaces of each namespace using the ip addr add command. This step establishes unique IP addresses for each namespace, enabling communication between them.

Setting Up Routing: Routing is set up within each namespace using the ip link set command. This step ensures that packets are correctly forwarded between interfaces within the same namespace.

Checking Connectivity: Connectivity between the namespaces is tested using the ping command. This step verifies that the namespaces can communicate with each other.

Establishing External Connectivity: External connectivity from the namespaces is tested using the ping command with external IP addresses. This step verifies if the namespaces can reach external networks.

Adding NAT Functionality: NAT (Network Address Translation) functionality is added to the host using the iptables command. This step allows the namespaces to access the internet by translating their private IP addresses to the host's public IP address.

Adding Default Gateways: Default gateways are added to each namespace using the ip route add command. This step ensures that packets destined for external networks are correctly routed through the host.

Adding Port Forwarding: Port forwarding rules are added to the host's iptables using the iptables command. This step allows incoming traffic on port 80 to be forwarded to specific destinations within the namespaces.

Viewing Network Namespaces, Bridge, and Virtual Ethernet Interfaces: The ip netns list, ip link show br0, and ip link show type veth commands are used to view the created network namespaces, the bridge interface, and the virtual Ethernet interfaces, respectively.

Analyzing Packet Traffic Using Python: A Python script is created using the Scapy library to capture and analyze packet traffic on the bridge interface. The script listens for IP packets and prints the source and destination IP addresses of each captured packet.

Now we start the implementation:

#------------------------Create 3 namespaces and packet send------------------------#

#Step1: Create the namespaces

-------

ip netns add ns1

ip netns add ns2

ip netns add ns3


#Step2: Create the bridge interface

-------

ip link add name br0 type bridge


#Step3: create a veth pair named $ns-inside and $ns-outside

-------

ip link add ns1-inside type veth peer name ns1-outside

ip link add ns2-inside type veth peer name ns2-outside

ip link add ns3-inside type veth peer name ns3-outside


#Step4: add the -outside half of the veth pair to the bridge and up

-------

ip link set dev ns1-outside master br0

ip link set dev ns2-outside master br0

ip link set dev ns3-outside master br0

ip link set ns1-outside up

ip link set ns2-outside up

ip link set ns3-outside up


#Step5: add the -inside half to the network namespace

-------

ip link set ns1-inside netns ns1

ip link set ns2-inside netns ns2

ip link set ns3-inside netns ns3


#Step6: add ip to namespaces

-------

ip netns exec ns1 ip addr add 10.0.0.1/24 dev ns1-inside

ip netns exec ns2 ip addr add 10.0.0.2/24 dev ns2-inside

ip netns exec ns3 ip addr add 10.0.0.3/24 dev ns3-inside


#Step7: Set up routing for the namespaces

-------

ip netns exec ns1 ip link set dev ns1-inside up

ip netns exec ns2 ip link set dev ns2-inside up

ip netns exec ns3 ip link set dev ns3-inside up

ip link set br0 up


#Step8: check Connectivity

-------

ip netns exec ns1 ping -c2 10.0.0.2     #from ns1

ip netns exec ns2 ping -c2 10.0.0.1     #from ns2

ip netns exec ns3 ping -c2 10.0.0.1     #from ns3


#------------------------Now set network for out of namespaces------------------------#

#now not rechable from host

ping 10.0.0.1#2/3


#Step9: set the IP 10.0.0.5 to this interface

-------

ip addr add 10.0.0.5/24 dev br0


#now rechable from host

ping 10.0.0.1#2/3


#don’t get any response back from the ping

ip netns exec ns1 ping 192.168.222.128

ip netns exec ns2 ping 192.168.222.128

ip netns exec ns3 ping 192.168.222.128


#Step10: Add a route entry

--------

ip netns exec ns1 ip route add 192.168.222.0/24 via 10.0.0.5

ip netns exec ns2 ip route add 192.168.222.0/24 via 10.0.0.5

ip netns exec ns3 ip route add 192.168.222.0/24 via 10.0.0.5


#get response back from the ping

ip netns exec ns1 ping 192.168.222.128

ip netns exec ns2 ping 192.168.222.128

ip netns exec ns3 ping 192.168.222.128


#dont get response back from the ping

ip netns exec ns1 ping 8.8.8.8

ip netns exec ns2 ping 8.8.8.8

ip netns exec ns3 ping 8.8.8.8


#Step11: Add NAT functionality to our host

--------

iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j MASQUERADE


#Step12: add a default gateway specifying our host

--------

ip netns exec ns1 ip route add default via 10.0.0.5

ip netns exec ns2 ip route add default via 10.0.0.5

ip netns exec ns3 ip route add default via 10.0.0.5


#get response back from the ping

ip netns exec ns1 ping 8.8.8.8

ip netns exec ns2 ping 8.8.8.8

ip netns exec ns3 ping 8.8.8.8


#Adding port forwarding rule to the host iptables

iptables -t nat -A PREROUTING --dport 80 --to-destination 10.0.0.1:80 -j DNAT

iptables -t nat -A PREROUTING --dport 80 --to-destination 10.0.0.2:80 -j DNAT

iptables -t nat -A PREROUTING --dport 80 --to-destination 10.0.0.3:80 -j DNAT


#show all net namespaces

ip netns list

#show bridge

ip link show br0

#check virtual eth

ip link show type veth


#----------------------get outerworld IP from namespaces by Python----------------------#

#Step13: run these 3 from individual terminal

--------

ip netns exec ns1 ping 8.8.8.8

ip netns exec ns2 ping 8.8.8.8

ip netns exec ns3 ping 8.8.8.8


#Step14: Create the python file

--------

cd /docker

vi nameSpacesIPtoNet.py

    from scapy.layers.inet import IP
    
    from scapy.all import sniff
    
    # Callback function to process captured packets
    
    def process_packet(packet):
    
        if packet.haslayer(IP):
        
            src_ip = packet[IP].src
            
            dst_ip = packet[IP].dst
            
            print(f"Source IP: {src_ip}\tDestination IP: {dst_ip}")
            
    # Sniff packets on the "br0" interface in promiscuous mode
    
    sniff(iface="br0", prn=process_packet, filter="ip")
    

#Step15: Run the python code

--------

python3 nameSpacesIPtoNet.py

    Source IP: 10.0.0.1     Destination IP: 8.8.8.8
    
    Source IP: 8.8.8.8      Destination IP: 10.0.0.1
    
    Source IP: 10.0.0.3     Destination IP: 8.8.8.8
    
    Source IP: 8.8.8.8      Destination IP: 10.0.0.3
    
    Source IP: 10.0.0.2     Destination IP: 8.8.8.8
    
    Source IP: 8.8.8.8      Destination IP: 10.0.0.2
    

