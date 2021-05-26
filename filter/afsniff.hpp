#ifndef AFSNIFF_HPP
#define AFSNIFF_HPP

#include <stdlib.h>
#include <stdio.h>
#include <cstdlib>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <boost/thread.hpp>

#include "ip.hpp"
#include "anomaly.hpp"
#include "exceptions.hpp"

#define MAX_BUFF 65537

/*
 * structure for ring buffer of AF_PACKET socket
 * contain pointer to a block of packets
*/
struct block_desc {
          uint32_t version;
          uint32_t offset_to_priv;
          struct tpacket_hdr_v1 h1;
 };
/*
 * class for AF_PACKET socket, which recieve and process packet 
 * @param ifacename: interface name for incoming packet, which also uses
 * for iptable blocking
 * @param: thread_: refrence to thread_group, this will be used to spawn new thread alongise others as a group.
 * @param: thread_anomaly: this will be used for each thread to process packet independently
 * @param: anomaly: for getting rule to be proccessed
 * @param: num_cpu_: number of cpu core for spawning multiple thread, this option currently intialize as 1, but
 * it can be used for implementing multiple thread as to support cpu fanout options. 
 * (this was not implemented becasue ring buffer gives us enough performance, and it seems better to replace AF_PACKET with something else. (pf_ring,...) )
 * @param: _enable_ring: to enable ring buffer
 * @param: rd_: vector of pointer to block of ring buffer, it will be used in ring buffer mode
 * @param: block_nr: number of block of buffer in rinf buffer mode
 *
*/
class AF_packet{
    
public:
    AF_packet(const std::string& ifname,boost::thread_group & grp,
            std::vector<std::shared_ptr<Anomaly>> & anom, const Anomaly & anoml, uint8_t p );
    ~AF_packet();
    void start();
    const uint8_t proto;

private:

    int get_iface_index(int fd,std::string if_name);
    int create_socket(int fanout);
    void packet_thread(int fd, int thread_id, std::shared_ptr<Anomaly> anom);
    static bool check_packet(const u_char * packet, std::shared_ptr<Anomaly> & anom,
        const unsigned int len, uint8_t ptoro_);
    void create_ring(int fd);
    static void read_block(struct block_desc * epbd, const unsigned int b_num
        , std::shared_ptr<Anomaly>& anom, uint8_t proto_ );
    
    std::string ifacename;
    boost::thread_group& thread_;
    std::vector<std::shared_ptr<Anomaly>>& thread_anomaly;
    Anomaly anomaly;
    int num_cpu_;
    bool _enable_ring;
    std::vector<std::unique_ptr<struct iovec>> * rd_;
    //place rule object here
    unsigned int block_nr;
};
#endif /* AFSNIFF_HPP */

