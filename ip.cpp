#include "ip.hpp"


//class tcpflag
tcp_flags::tcp_flags()
    : enable(false), bits_(std::string("000000")),
    mask_(std::string("000000")) {}
tcp_flags::tcp_flags(const std::pair<std::bitset<6>, std::bitset<6>>& flags)
    : enable(true), bits_(flags.first), mask_(flags.second) {}
bool tcp_flags::in_this(const std::bitset<6>& flags) const
{
    if((flags&mask_) == bits_)
        return true;
    return false;
}
bool tcp_flags::operator==(tcp_flags const & other) const
{
    return (bits_ == other.bits_
            && mask_ == other.mask_
            && enable == other.enable);
}

//class NumRange
template<class T> 
NumRange<T>::NumRange():start_(0),end_(0),enable_(false){}
template<class T>
NumRange<T>::NumRange(const std::pair<T, T>& p)
    : start_(p.first), end_(p.second), enable_(true) {}
template<class T>
NumRange<T>& NumRange<T>::operator=(const std::pair<T, T>& p)
{
    if(p.first != 0 || p.second != 0)
    {
        start_ = p.first;
        end_ = p.second;
        enable_ = true;
    }
    return *this;
}
template<class T>
bool NumRange<T>::in_this(T num) const
{
    if(!enable_)
        return true;
    if(num != 0 && num >= start_ && num <= end_)
    {
        return true;
    }
    else
    {
        return false;
    }
}
template<class T>
bool NumRange<T>::stat() const
{
    return enable_;
}
template<class T>
std::string NumRange<T>::to_string() const
{
    return std::to_string(start_) + "-" +std::to_string(end_);
}
//class NumComparable
template<class T>
NumComparable<T>::NumComparable()
    : num_(0), type_(0), enable_(false) {}
template<class T>
NumComparable<T>::NumComparable(const std::pair<T, unsigned short int>& p)
    : num_(p.first), type_(p.second), enable_(true){}
template<class T>
NumComparable<T>& NumComparable<T>::operator=(const std::pair<T, unsigned short int>& p)
{
    num_ = p.first;
    type_ = p.second;
    enable_ = true;
    return *this;
}
template<class T>
bool NumComparable<T>::in_this(T num) const
{
    if(!enable_)
        return true;
    if(type_ == 0 && num == num_)
        return true;
    if(type_ == 1 && num > num_)
        return true;
    if(type_ == 2 && num < num_)
        return true;
    return false;
}
template<class T>
bool NumComparable<T>::stat() const
{
    return enable_;
}
template<class T>
std::string NumComparable<T>::to_string() const
{
    return std::to_string(type_) + ":" + std::to_string(num_);
}

//class ipv4
IpRule::IpRule(uint8_t proto):protocol(proto), pps_trigger(0), bps_trigger(0){}
IpRule::IpRule(uint8_t proto,const std::vector<std::string>& tkn_rule):
    protocol(proto), pps_trigger(0), bps_trigger(0),tkn_(tkn_rule){}
void IpRule::ip_rule_parse(const boost::program_options::variables_map& vm){
 
    if (vm.count("srcip")) {
        src_addr = parser::range_from_ip_string(vm["srcip"].as<std::string>());
    }
    if (vm.count("dstip")) {
	std::pair<uint32_t,uint32_t> tmp = parser::range_from_ip_string(vm["dstip"].as<std::string>());
        dst_addr = boost::asio::ip::make_address_v4(tmp.first).to_ulong();
    }
    
    if (vm.count("pps-th")) {
        pps_trigger = parser::from_short_size(vm["pps-th"].as<std::string>(), false);
    }
    if (vm.count("bps-th")) {
        bps_trigger = parser::from_short_size(vm["bps-th"].as<std::string>());
    }
   
    if(pps_trigger == 0 && bps_trigger == 0)
        throw ParserException("pps or bps trigger will be set");
    
    
}

/*uint32_t IPRule::get_addr(){
    return dst_addr;   
}
*/
//class tcp
Tcp::Tcp():IpRule(6){}
Tcp::Tcp(const std::vector<std::string>& tkn_rule):IpRule(6, tkn_rule){

    namespace po = boost::program_options;
    _opt.add_options()
        ("pps-th", po::value<std::string>(), "trigger threshold incomming packets per second (p,Kp,Mp,Tp,Pp)")
        ("bps-th", po::value<std::string>(), "trigger threshold incomming bits per second (b,Kb,Mb,Tb,Pb)")
        ("dstip,d", po::value<std::string>(), "destination ip address/net")
        ("srcip,s", po::value<std::string>(), "source ip address/net")
        ("dport", po::value<std::string>(), "destination port")
        ("sport", po::value<std::string>(), "source port")
        ("seq", po::value<std::string>(), "check if sequence number = or > or < arg")
        ("win", po::value<std::string>(), "check if window size number = or > or < arg")
        ("ack", po::value<std::string>(), "check if acknowledgment number = or > or < arg")
        ("hlen", po::value<std::string>(), "check if TCP header len = or > or < arg (in bytes)")
        ("tcp-flag", po::value<std::string>(), "TCP flags <flag>:<enable>, where <enable> - 1 or 0; <flag> - U or R or P or S or A or F.")
    ;

}
void Tcp::parse(){
    
    parser::CommandParser cp(_opt);
    boost::program_options::variables_map vm = cp.parse(tkn_);
    // parse L3 header
    ip_rule_parse(vm);
    // parse L4 header
    if (vm.count("sport")) {
        sport = parser::range_from_port_string(vm["sport"].as<std::string>());
    }
    if (vm.count("dport")) {
        dport = parser::range_from_port_string(vm["dport"].as<std::string>());
    }
    if (vm.count("seq")) {
        seq = parser::numcomp_from_string<uint32_t>(vm["seq"].as<std::string>());
    }
    if (vm.count("ack")) {
        ack = parser::numcomp_from_string<uint32_t>(vm["ack"].as<std::string>());
    }
    if (vm.count("win")) {
        win = parser::numcomp_from_string<uint16_t>(vm["win"].as<std::string>());
    }
    if (vm.count("hlen")) {
        len = parser::numcomp_from_string<uint16_t>(vm["hlen"].as<std::string>());
    }
    if (vm.count("tcp-flag")) {
        std::string flag_opt = vm["tcp-flag"].as<std::string>();
        flags = parser::bitset_from_string<std::bitset<6>>(flag_opt,
                                                    tcprule::accept_tcp_flags);
    }
    
}
bool Tcp::check_packet(const void * hdr,
           const uint32_t s_addr,const uint32_t d_addr) const{
    
    const struct tcphdr * tcp_hdr = (struct tcphdr *) hdr;
    if(!src_addr.in_this(s_addr)) // check source ip address
        return false;
    if(dst_addr != d_addr) // check destination ip address
        return false;
    // L4 header check
#if defined (__FreeBSD__)
    uint16_t h_sport = ntohs(tcp_hdr->th_sport);
#elif defined(__linux__)
    uint16_t h_sport = ntohs(tcp_hdr->source);
#endif
    if(!sport.in_this(h_sport))
        return false;
#if defined (__FreeBSD__)
    uint16_t h_dport = ntohs(tcp_hdr->th_dport);
#elif defined(__linux__)
    uint16_t h_dport = ntohs(tcp_hdr->dest);
#endif
    if(!dport.in_this(h_dport))
        return false;
#if defined (__FreeBSD__)
    uint32_t h_seq = ntohl(tcp_hdr->th_seq);
#elif defined(__linux__)
    uint32_t h_seq = ntohl(tcp_hdr->seq);
#endif
    if(!seq.in_this(h_seq))
        return false;
#if defined (__FreeBSD__)
    uint32_t h_ack = ntohl(tcp_hdr->th_ack);
#elif defined(__linux__)
    uint32_t h_ack = ntohl(tcp_hdr->ack_seq);
#endif
    if(!ack.in_this(h_ack))
        return false;
#if defined (__FreeBSD__)
    uint16_t h_win = ntohs(tcp_hdr->th_win);
#elif defined(__linux__)
    uint16_t h_win = ntohs(tcp_hdr->window);
#endif
    if(!win.in_this(h_win))
        return false;
#if defined (__FreeBSD__)
    uint16_t h_len = tcp_hdr->th_off * 4;
#elif defined(__linux__)
    uint16_t h_len = tcp_hdr->doff * 4;
#endif
    if(!len.in_this(h_len))
        return false;
    if(flags.enable)
    {
#if defined (__FreeBSD__)
        std::bitset<6> h_flags(tcp_hdr->th_flags);
#elif defined(__linux__)
        std::bitset<6> h_flags;
        h_flags[0] = tcp_hdr->urg;
        h_flags[1] = tcp_hdr->ack;
        h_flags[2] = tcp_hdr->psh;
        h_flags[3] = tcp_hdr->rst;
        h_flags[4] = tcp_hdr->syn;
        h_flags[5] = tcp_hdr->fin;
#endif
        if(!flags.in_this(h_flags))
            return false;
    }

    return true;
}

//class udp
Udp::Udp():IpRule(17){}
Udp::Udp(const std::vector<std::string>& tkn_rule):IpRule(6, tkn_rule){
    
    namespace po = boost::program_options;
    _opt.add_options()
        ("pps-th", po::value<std::string>(), "trigger threshold incomming packets per second (p,Kp,Mp,Tp,Pp)")
        ("bps-th", po::value<std::string>(), "trigger threshold incomming bits per second (b,Kb,Mb,Tb,Pb)")
        ("dstip,d", po::value<std::string>(), "destination ip address/net")
        ("srcip,s", po::value<std::string>(), "source ip address/net")
        ("dport", po::value<std::string>(), "destination port")
        ("sport", po::value<std::string>(), "source port")
        ("hlen", po::value<std::string>(), "check if UDP header len = or > or < arg (in bytes)")
    ;

}
void Udp::parse(){
    
    parser::CommandParser cp(_opt);
    boost::program_options::variables_map vm = cp.parse(tkn_);
    // parse L3 header
    ip_rule_parse(vm);
    // parse L4 header
    if (vm.count("sport")) {
        sport = parser::range_from_port_string(vm["sport"].as<std::string>());
    }
    if (vm.count("dport")) {
        dport = parser::range_from_port_string(vm["dport"].as<std::string>());
    }
    if (vm.count("hlen")) {
        len = parser::numcomp_from_string<uint16_t>(vm["hlen"].as<std::string>());
    }
    
}

bool Udp::check_packet(const void * hdr,
           const uint32_t s_addr,const uint32_t d_addr) const{

    const struct udphdr * udp_hdr = (struct udphdr *) hdr;
    
     if(!src_addr.in_this(s_addr)) // check source ip address
        return false;
    if( dst_addr != d_addr ) // check destination ip address
        return false;
    // L4 header check
#if defined (__FreeBSD__)
    uint16_t h_sport = ntohs(udp_hdr->uh_sport);
#elif defined (__linux__)
    uint16_t h_sport = ntohs(udp_hdr->source);
#endif
    if(!sport.in_this(h_sport))
        return false;
#if defined (__FreeBSD__)
    uint16_t h_dport = ntohs(udp_hdr->uh_dport);
#elif defined (__linux__)
    uint16_t h_dport = ntohs(udp_hdr->dest);
#endif
    if(!dport.in_this(h_dport))
        return false;
#if defined (__FreeBSD__)
    uint16_t h_len = udp_hdr->uh_ulen;
#elif defined (__linux__)
    uint16_t h_len = udp_hdr->len;
#endif
    if(!len.in_this(h_len))
        return false;

    return true;
    
}

//class icmp
Icmp::Icmp():IpRule(1){}
Icmp::Icmp(const std::vector<std::string>& tkn_rule):IpRule(6, tkn_rule){

    namespace po = boost::program_options;
    _opt.add_options()
        ("pps-th", po::value<std::string>(), "trigger threshold incomming packets per second (p,Kp,Mp,Tp,Pp)")
        ("bps-th", po::value<std::string>(), "trigger threshold incomming bits per second (b,Kb,Mb,Tb,Pb)")
        ("dstip,d", po::value<std::string>(), "destination ip address/net")
        ("srcip,s", po::value<std::string>(), "source ip address/net")
        ("type", po::value<std::string>(), "check if ICMP packet type = or > or < arg")
        ("code", po::value<std::string>(), "check if ICMP packet code = or > or < arg")
    ;    


}
void Icmp::parse(){
    
    parser::CommandParser cp(_opt);
    boost::program_options::variables_map vm = cp.parse(tkn_);
    // parse L3 header
    ip_rule_parse(vm);
    // parse L4 header
    if (vm.count("type")) {
        type = parser::numcomp_from_string<uint8_t>(vm["type"].as<std::string>());
    }
    if (vm.count("code")) {
        code = parser::numcomp_from_string<uint8_t>(vm["code"].as<std::string>());
    }
}
bool Icmp::check_packet(const void * hdr,
           const uint32_t s_addr,const uint32_t d_addr) const{
    
    const struct icmphdr * icmp_hdr = (struct icmphdr *) hdr;
      // L3 header check
    if(!src_addr.in_this(s_addr)) // check source ip address
        return false;
    if(dst_addr != d_addr) // check destination ip address
        return false;
    // L4 header check
#if defined (__FreeBSD__)
    uint8_t h_type = icmp_hdr->icmp_type;
#elif defined (__linux__)
    uint8_t h_type = icmp_hdr->type;
#endif
    if(!type.in_this(h_type))
        return false;
#if defined (__FreeBSD__)
    uint8_t h_code = icmp_hdr->icmp_code;
#elif defined (__linux__)
    uint8_t h_code = icmp_hdr->code;
#endif
    if(!code.in_this(h_code))
        return false;

    return true;


}













