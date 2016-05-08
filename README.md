# SimpleIPv6Knockin
This is just a simple IPv6 Knocking program. Will let you execute commands on a server side based on a source IP combination. 
#### 1.1 Installation
This program just needs Scapy to be executed. You can install it from your distro repository or download it from Scapy website.
######  1.1.1 Scapy from repository
```sh
sudo apt-get install python-scapy
```
######  1.1.2 Scapy from website
```sh
$ cd /tmp
$ wget scapy.net
$ unzip scapy-latest.zip
$ cd scapy-2.*
$ sudo python setup.py install
```
Alternatively, you can execute the zip file:
```sh
$ chmod +x scapy-latest.zip
$ sudo ./scapy-latest.zip
```

#### 1.2 Using the program 
You can use this program as a knocking protocol to execute different commands on a remote system based on different source IPv6 (remember that /64 is assigned to the user). When the server detects that a valid sequence has been received, it will execute the configured system command. You can use this to start or stop different services on your server (like SSH, Apache, etc.). In summary, this program is a latch for your live services, so you can start and stop them whenever you need. You can select between TCP or UDP protocol in order to receive the valid sequence. You can also choose the destination port narrowing the scope of possible brute forcing attacks. 

##### 1.2.1 Usage on client side
```sh
Flags:
    -a  --action    Set action to be executed on a remote system [open|close]
    -f  --files     Use config files to execute commands on a remote system
    -v  --verbose   Set verbose mode

Examples:
    SimpleIP6Knocking_client.py -a open -f config_file_1.cfg
    SimpleIP6Knocking_client.py -v -a close -f config_file_1.cfg config_file_2.cfg
```
##### 1.2.2 Tutorial video
https://youtu.be/jWFutlGePb4

[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/jWFutlGePb4/0.jpg)](https://www.youtube.com/watch?v=jWFutlGePb4)

# IPv6 Basics
### 2.1 IPv6 description
    An Internet Protocol Version 6 address (IPv6 address) is a numerical label that is used to identify a network interface of a computer or other network node participating in an IPv6 computer network.
    An IP address serves the purpose of uniquely identifying an individual network interface of a host, locating it on the network, and thus permitting the routing of IP packets between hosts. For routing, IP addresses are present in fields of the packet header where they indicate source and destination of the packet.
    IPv6 is the successor to the first addressing infrastructure of the Internet, Internet Protocol version 4 (IPv4). In contrast to IPv4, which defined an IP address as a 32-bit value, IPv6 addresses have a size of 128 bits. Therefore, IPv6 has a vastly enlarged address space compared to IPv4.
    An IPv6 address consists of 128 bits. Addresses are classified into various types for applications in the major addressing and routing methodologies: unicast, multicast, and anycast networking. In each of these, various address formats are recognized by logically dividing the 128 address bits into bit groups and establishing rules for associating the values of these bit groups with special addressing features.

More information: 
    - https://en.wikipedia.org/wiki/IPv6_address
    - https://www.ietf.org/rfc/rfc2460.txt
