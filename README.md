# DDosMitigation

The system is written in C++(Standard 17) and Boost(1.75). Writing is done on Ubutu 16.04.4 and compiler g++-7(7.3.0).
The program tested with cppcheck

# Dependencies

sudo apt install sqlite3 libsqlite3-dev iptables-dev libevent-dev quagga-bgpd

# Install

clone and make the program.

# Run
./Supervisor


Configuration file:
You need to place taro.conf in /etc/ddosdetector.conf, chage values as desired.
You need also create rules file (/etc/ddosdetector.rules)
The formats are discussed as bellow.

\<protocol\> -d \<destination-ip\> --pps-th \<packet-threshold\> --bps-th \<byte-threshold\> [--tcp-flag R:1, S:0] --dport \<destination-port\> --filter \<type:ratio\>
  
 TCP -d 192.168.1.142/32 --pps-th 7p --tcp-flag R:1 --dport 220-500 --filter src_ip:1
 
 This will enable src_ip filter for specific ip and port range, for reset flag, if packets reaches above 7 packet per second limit.

ICMP -d 192.168.1.1/32 --bps-th 10Mb --pps-th-period --type 8>  --filter src_ip:1,icmp_type:1
