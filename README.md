<img width="523" alt="NameSpacesNet" src="https://github.com/MdAhosanHabib/LinuxNetworkingNamespace/assets/43145662/3cc0a3fa-ae79-4af8-84ce-f8e1c8a0ed4d">

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

