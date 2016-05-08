# SimpleIPv6Knockin
This is just a simple IPv6 Knocking program. Will let you execute commands on a server side based on a source IP combination. 
####1.1 Installation
This program just needs Scapy to be executed. You can install it from your distro repository or get it from Scapy website.
######1.1.1 Scapy from repository
```sh
sudo apt-get install python-scapy
```
######1.1.2 Scapy from website
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

####1.2 Using the program 
You can use this program as a knocking protocol to execute different commands on a remote system based on different source IPv6 (remember that /64 is assigned to the user). When the server detects that a valid sequence has been received, it will execute the configured system command. This is useful to start or stop different services on the server side (like SSH, Apache, etc.). Briefing, this program is a latch for your live services, so you can start and stop them whenever you need. TCP or UDP protocols are both available in order to receive the valid sequence. You can also choose the destination port narrowing the scope of possible brute forcing attacks. 

Using IPv6 you are able to send any packet included into your /64 network. Using that characteric of IPv6, this program detects if the last octets of the source IP complains a valid sequence. When a valid sequence is detected, the configured program is executed on the listening host. 

#####1.2.1 Usage on client side
```sh
python SimpleIPv6Knocking_client.py -h
Flags:
    -a  --action    Set action to be executed on a remote system [open|close]
    -f  --files     Use config files to execute commands on a remote system
    -v  --verbose   Set verbose mode

Examples:
    SimpleIP6Knocking_client.py -a open -f config_file_1.cfg
    SimpleIP6Knocking_client.py -v -a close -f config_file_1.cfg config_file_2.cfg
```

You need to configure the config.cfg file which contains the needed information to send a valid sequence to the remote host. This file contains the destination port, transport protocol to be used (UDP/TCP), the valid sequences (to open or close services), the destination address and the local interface to send the proper sequence. The configuration file contains: 
 ```sh
[network_config]
destination_address = fe80::a00:27ff:fe8a:93ba
interface = eth0
destination_port = 22
protocol = udp

[valid_sequences]
open_sequence = bbb,ccc,aaa
close_sequence = 111,222,333
```

#####1.2.2 Usage on server side
Execute the program as a service or in the background. This program will listen all the packets sended to the configured interface which complains the protocol and port configuration. If a valid sequence is received (open) the program will execute the configured open command. When the open command has been executed, the program will wait until the close sequence is received to execute the close command. It will be listening forever unless you stop de application. The configuration file (server_config.cfg) contains the server configuration which includes: 

```sh
[network_config]
iface = eth1
destination_port = 22
protocol = udp

# Valid IPv6 end sequence to execute commands on the server side
[valid_sequences]
open_sequence = bbb,ccc,aaa
close_sequence = 111,222,333

# Commands to be executed when a valid sequence is detected
[commands]
open_command = sudo start ssh
close_command = sudo stop ssh
```
Executing the program: 

```sh
sudo python SimpleIPv6Knocking_server.py
```
Or in background: 
```sh
sudo nohup python SimpleIPv6Knocking_server.py &
```

####1.3 Tutorial video
https://youtu.be/jWFutlGePb4

[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/jWFutlGePb4/0.jpg)](https://www.youtube.com/watch?v=jWFutlGePb4)

####1.4 IPv6 Basics


More information: 
    - https://en.wikipedia.org/wiki/IPv6_address
    - https://www.ietf.org/rfc/rfc2460.txt
