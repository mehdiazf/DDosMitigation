/* 
 * File:   newmain.cpp
 * Author: azf
 *
 * Created on March 15, 2021, 12:30 PM
 */
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
#include <sys/types.h>
#include <boost/thread.hpp>

#define MAX_BUFF 65536

unsigned int icmp=0;
unsigned int icmp_len=0;
unsigned int udp=0;
unsigned int udp_len=0;
unsigned int tcp=0;
unsigned int tcp_len=0;
unsigned int other=0;
unsigned int other_len=0;

boost::mutex mtx;


void show_result(){

    time_t lst = std::time(0);
    time_t now;
    while(1){
        boost::this_thread::sleep(boost::posix_time::seconds(2));
        now = std::time(0);
        if(now - lst > 2){
            boost::lock_guard<boost::mutex> g(mtx);
            system("clear");
            std::cout<<"TCP: ("<< (double)tcp/(now-lst) <<" pps)"<<
                    " ("<< (double) tcp_len/(now-lst)<<" bps)"<<std::endl;
            std::cout<<"UDP: ("<< (double)udp/(now-lst) <<" pps)"<<
                    " ("<< (double) udp_len/(now-lst)<<" bps)"<<std::endl;
            std::cout<<"ICMP: ("<< (double)icmp/(now-lst) <<" pps)"<<
                    " ("<< (double) icmp_len/(now-lst)<<" bps)"<<std::endl;
            std::cout<<"Other: ("<< (double)other/(now-lst) <<" pps)"<<
                    " ("<< (double) other_len/(now-lst)<<" bps)"<<std::endl;
            tcp=0; tcp_len=0;
            udp=0; udp_len=0;
            icmp=0; icmp_len=0;
            other=0; other_len=0;
        }
        
    }
    
}

int get_iface_index(int fd,std::string if_name){
    
    struct ifreq ifr;
    size_t if_name_len = if_name.size();

    if (if_name_len < sizeof(ifr.ifr_name)) {
        strncpy(ifr.ifr_name,if_name.c_str(), if_name.size());
    } 
    else {
        throw std::invalid_argument("interface name is too long");
        //return -1;
    }
    
    if (ioctl(fd,SIOCGIFINDEX, &ifr) == -1) {
        throw std::exception();
        //return -1;
    }
    
    int ifindex = ifr.ifr_ifindex;
    return ifindex;
    
}
void parse_pack(unsigned char * buffer, unsigned int len){
    
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    boost::lock_guard<boost::mutex> gg(mtx);
    switch(iph->protocol){
        case 1:
            icmp++;
            icmp_len+=len;
            break;
        case 6:
            tcp++;
            tcp_len+=len;
            break;
        case 17:
            udp++;
            udp_len+=len;
            break;
        default:
            other++;
            other_len+=len;
            break;           
    }
}
void start_af_packet(std::string ifacename, int fanout, int thread_id){
    
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    if(fd == -1)
       throw  std::exception();
    
    int ifindex = get_iface_index(fd,ifacename);
    
    struct sockaddr_ll bind_addr;
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ALL);
    bind_addr.sll_ifindex = ifindex;
    
    if( bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr))==-1 )
        throw std::exception();
    
    int arg = (fanout | PACKET_FANOUT_CPU<<16);
    if( setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &arg, sizeof(arg)) < 0)
        throw std::exception();
    
    //std::cout<<"Capturing is starting: "<<thread_id<<std::endl;
    
    //get_packet();
    
    size_t read_len;
    unsigned char buff[MAX_BUFF];
    while(true){
        read_len=recv(fd, buff, MAX_BUFF, MSG_TRUNC);
        if (read_len < 0)
            if(errno==EAGAIN || errno==EINTR)
                continue;
            else    
                return;  
            
        parse_pack(buff,read_len);    
        
    }
    
    
}
//using namespace std;
int main(int argc, char** argv) {

    boost::thread_group thr_gp;
    int fanout_group_id = getpid() & 0xffff;
     
    try{
    for(int i=0;i<2;i++)
        thr_gp.add_thread(new boost::thread(boost::bind(start_af_packet,"ens160",fanout_group_id,i)));
    }
    catch(...){
        std::cout<< "can't spawn threads! "<<std::endl;
    }
    thr_gp.add_thread(new boost::thread(show_result)); 
            
    thr_gp.join_all();
}

