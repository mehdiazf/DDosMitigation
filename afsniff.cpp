#include "afsniff.hpp"

AF_packet::AF_packet(std::string ifname,boost::thread_group & grp,
            std::vector<std::shared_ptr<Anomaly>> & anom,
        const Anomaly & anoml, uint8_t p ):proto(p),ifacename(ifname),
        thread_(grp),thread_anomaly(anom),anomaly(anoml),num_cpu_(1),
        _enable_ring(1),rd_(nullptr){}

AF_packet::~AF_packet(){
    
    if(_enable_ring)
        delete rd_;
    
}

void AF_packet::start(){
    
    int fanout_group_id = getpid() & 0xffff;
    
    try{
        
        for(int i=0;i<num_cpu_;i++){
            int fd = create_socket(fanout_group_id);
            auto _ptr = std::make_shared<Anomaly>(anomaly);
            thread_anomaly.push_back(_ptr);
            thread_.add_thread(new boost::thread(&AF_packet::packet_thread, this, fd, i, _ptr));
        }
    }
    catch(...){
        throw AfpacketException("couldn't create threads.");
        ///logger
    }
       
}
 bool AF_packet::check_packet(const u_char * packet, std::shared_ptr<Anomaly> & anom,
        const unsigned int len, uint8_t proto_){
     
    struct ether_header *eth_header = (struct ether_header *) packet;
    if (eth_header->ether_type != htons(ETHERTYPE_IP)) {
        return false; // pass non-ip packet
    }

    // IP header
    struct ip *ip_hdr = (struct ip *) (packet + sizeof(struct ether_header));
    int size_ip = ip_hdr->ip_hl * 4;

    if(proto_ == 6)
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        // TCP Header
        struct tcphdr *tcp_hdr = (struct tcphdr*) (packet +
                                                   sizeof(struct ether_header) +
                                                   size_ip);
        return anom->check_packet(tcp_hdr,
                                  ntohl(ip_hdr->ip_src.s_addr),
                                  ntohl(ip_hdr->ip_dst.s_addr),
                                  len);
    }
    
    if(proto_ == 17)
    if (ip_hdr->ip_p == IPPROTO_UDP) {
        // UDP Header
        struct udphdr *udp_hdr = (struct udphdr*) (packet +
                                                   sizeof(struct ether_header) +
                                                   size_ip);
        return anom->check_packet(udp_hdr,
                                  ntohl(ip_hdr->ip_src.s_addr),
                                  ntohl(ip_hdr->ip_dst.s_addr),
                                  len);
    }
    
    if(proto_ == 1)
    if (ip_hdr->ip_p == IPPROTO_ICMP) {
        // ICMP Header
        struct icmphdr *icmp_hdr = (struct icmphdr*) (packet +
                                                      sizeof(struct ether_header) +
                                                      size_ip);
        return anom->check_packet(icmp_hdr,
                                  ntohl(ip_hdr->ip_src.s_addr),
                                  ntohl(ip_hdr->ip_dst.s_addr),
                                  len);
    }
    return false;
                      
 }
void AF_packet::read_block(struct block_desc * epbd, const unsigned int b_num
    , std::shared_ptr<Anomaly>& anom, uint8_t proto_ ){
    
    int num_pkts = epbd->h1.num_pkts;
           struct tpacket3_hdr *ppd;
  
           ppd = (struct tpacket3_hdr *) ((uint8_t *) epbd + epbd->h1.offset_to_first_pkt);
           for(int i=0; i<num_pkts; i++){
                    check_packet(((uint8_t *) ppd + ppd->tp_mac), anom, ppd->tp_snaplen, proto_);
                    ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd + ppd->tp_next_offset);
                    }

    
}
void AF_packet::packet_thread(int fd, int thread_id, std::shared_ptr<Anomaly> anom){
    
    size_t read_len;
    unsigned char buff[MAX_BUFF];
    try
    {        
        if(!_enable_ring)
        {
            
            while(true)
            {
                //boost::this_thread::interruption_point();
                read_len = recv(fd, buff, MAX_BUFF, MSG_TRUNC);
                if (read_len < 0)
                {
                    if(errno==EAGAIN || errno==EINTR)
                        continue;
                    else    
                        return;  
                }
                //if(
                    check_packet(buff, anom, read_len, proto); ////capture
            }
        }
        else
        {
            unsigned int nb = 0;
            struct pollfd pfd;
            struct block_desc *epbd;
            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = fd;
            pfd.events = POLLIN | POLLERR;
            pfd.revents = 0;            
            while(true){
                   epbd = (struct block_desc *) rd_->operator[](nb)->iov_base;                   
                    if((epbd->h1.block_status & TP_STATUS_USER) == 0){
                            poll(&pfd, 1, -1);
                            continue;
                    }
   
                    read_block(epbd, nb, anom , proto);
                    epbd->h1.block_status = TP_STATUS_KERNEL;
                    nb = (nb +1) % block_nr;
   
             }
            
        }
        
    }
    catch(...)
    {
        close(fd);
        throw AfpacketException("thread " + std::to_string(thread_id) + " closed.");
    }
}
int AF_packet::get_iface_index(int fd, std::string if_name){
    
     struct ifreq ifr;
    size_t if_name_len = if_name.size();

    if (if_name_len < sizeof(ifr.ifr_name)) {
        strncpy(ifr.ifr_name,if_name.c_str(), if_name.size());
    } 
    else {
        throw AfpacketException("interface name is too long");
        //return -1;
    }
    
    if (ioctl(fd,SIOCGIFINDEX, &ifr) == -1) {
        throw AfpacketException("cant get interface index.");
        //return -1;
    }
    
    int ifindex = ifr.ifr_ifindex;
    return ifindex;
    
}
void AF_packet::create_ring( int fd){
    
    int v = TPACKET_V3;
        int sts = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof (v));
        if (sts < 0)
            throw  AfpacketException("Setting to packet_version 3 failed.");
        
        auto ps= sysconf(_SC_PAGESIZE);
        unsigned int block_size = ps<<3, frame_size = 1<<11;
       if(block_size < frame_size)
           frame_size = ps;
       unsigned int block_num = 32;
 
        struct tpacket_req3 req;
        memset(&req, 0, sizeof(req));
        req.tp_block_size = block_size;
        req.tp_frame_size = frame_size;
        req.tp_block_nr = block_num;
        req.tp_frame_nr = (block_num * block_size) / frame_size;  
        block_nr = req.tp_block_nr;
        
        sts = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
        if(sts < 0)
           throw  AfpacketException("PCKET_RX_RING failed.");

        uint8_t * _map = static_cast<uint8_t*>( mmap(NULL, req.tp_block_size * req.tp_block_nr, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED,fd, 0));
        if(_map == MAP_FAILED)
            throw  AfpacketException("failed to map rx_rings.");
 
 
        rd_ = new std::vector<std::unique_ptr<struct iovec>>(req.tp_block_nr);
        for( unsigned int i=0; i<req.tp_block_nr; i++){
            rd_->operator [](i) = std::make_unique<struct iovec>();
            rd_->operator [](i)->iov_base = _map + (i * req.tp_block_size);
            rd_->operator [](i)->iov_len = req.tp_block_size;
           }        
        if(rd_ == nullptr)
            throw  AfpacketException("Cant crate ring buffer.");
}

int AF_packet::create_socket(int fanout){
    
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    if(fd == -1)
       throw  AfpacketException("binding interface" + ifacename + "failed.");
    
    
    if(_enable_ring)
        create_ring(fd);                
            
    
    int ifindex = get_iface_index(fd,ifacename);    
    struct sockaddr_ll bind_addr;
    bind_addr.sll_family = AF_PACKET;
    bind_addr.sll_protocol = htons(ETH_P_ALL);
    bind_addr.sll_ifindex = ifindex;        
    
    if( bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr))==-1 )
        throw  AfpacketException("binding interface" + ifacename + "failed.");
    
    int arg = (fanout | PACKET_FANOUT_CPU<<16);
    if( setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &arg, sizeof(arg)) < 0)
        throw  AfpacketException("binding interface" + ifacename + "failed.");
    
    
    return fd;
    
    
}
