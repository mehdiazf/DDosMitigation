# DDos-mitigation

The system is written in C++(Standard 17) and Boost(1.75). Writing is done on Ubutu 16.04.4 and compiler g++-7(7.3.0).

# Run
#./filter condition

Note: the rule for enabling alert is shown bellow:

<protocol> -d <destination-ip> --pps-th <packet-threshold> --bps-th <byte-threshold> [--tcp-flag R:1, S:0] --dport <destination-port> --filter <type:ratio>
  
 TCP -d 192.168.1.142/32 --pps-th 7p --tcp-flag R:1 --dport 220-500 --filter src_ip:1
 
 This will enable src_ip filter for specific ip and port range, for reset flag, if packets reaches above 7 packet per second limit.
