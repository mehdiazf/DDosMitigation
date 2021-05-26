#ifndef IP_HPP
#define IP_HPP

#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <iostream>
#include <sys/types.h>
#include <map>
#include <bitset>
#include <string>
#include <boost/program_options.hpp>
#include <boost/asio/ip/address_v4.hpp>

class Iptable;
namespace tcprule
{
    // Textual representation of TCP flags in the correct order, for
    // parsing rules
    const std::vector<char> accept_tcp_flags = { 'U', 'A', 'P', 'R', 'S', 'F' };
}

class tcp_flags
{
public:
    tcp_flags();
    tcp_flags(const std::pair<std::bitset<6>, std::bitset<6>>& flags);
    bool operator==(const tcp_flags& other) const;
        // Comparison of bits in flags with parameter bits_ by mask mask_
    bool in_this(const std::bitset<6>& flags) const;

    bool enable;
private:
    // Flag bits
    std::bitset<6> bits_;
    // Comparison mask
    std::bitset<6> mask_;
};
/*
 * template class for range data (ip, port)
*/
template<class T>
class NumRange{
    public:
        NumRange();
        explicit NumRange(const std::pair<T,T>& o);
        NumRange& operator=(const std::pair<T,T>& o);
        bool in_this(T num) const;
        bool stat() const;
        std::string to_string() const;

	friend class Iptable;    
    private:
        T start_;
        T end_;
        bool enable_;
};
/*
 * template class for conmparable value
*/ 
template<class T>
class NumComparable{
    public:
        NumComparable();
        explicit NumComparable(const std::pair<T,unsigned short int>& o);
        NumComparable& operator=(const std::pair<T,unsigned short int>& o);
        bool in_this(T num) const;
        bool stat() const;
        std::string to_string() const;

	//friend class Iptable;        
    private:
        T num_;
        unsigned short int type_;
        bool enable_;
    
};
/*
 * class for L3 parmeters and general parameter like pps_trigger
*/
class IpRule{
    
public:
    IpRule(uint8_t proto);
    explicit IpRule(uint8_t proto, const std::vector<std::string>& tkn_rule);
    void ip_rule_parse(const boost::program_options::variables_map& vm);
    virtual bool check_packet(const void * hdr,
                      const uint32_t s_addr,
                      const uint32_t d_addr) const =0 ;
    virtual void parse() =0;    
    
    uint8_t protocol;
    NumRange<uint32_t> src_addr;
    uint32_t dst_addr;
    uint32_t pps_trigger;                        
    uint32_t bps_trigger;
    std::vector<std::string> tkn_;
};
/*
 * tcp class for L4 parameters
*/
class Tcp: public IpRule{
    
public:
    Tcp();
    explicit Tcp(const std::vector<std::string>& tkn_rule);
    void parse();
    bool check_packet(const void * hdr,
                      const uint32_t s_addr,
                      const uint32_t d_addr) const override;
    
    NumRange<uint16_t> dport;
    NumRange<uint16_t> sport;
    NumComparable<uint8_t> len;
    NumComparable<uint16_t> win;
    NumComparable<uint32_t> seq;
    NumComparable<uint32_t> ack;
    tcp_flags flags;
    boost::program_options::options_description _opt;
    
};
/*
 * udp class for L4 parameters
*/
class Udp: public IpRule{
        
public:
    Udp();
    explicit Udp(const std::vector<std::string>& tkn_rule);
    void parse();
    bool check_packet(const void * hdr,
                      const uint32_t s_addr,
                      const uint32_t d_addr) const override;  
    NumRange<uint16_t> dport;
    NumRange<uint16_t> sport;
    NumComparable<uint8_t> len;
    boost::program_options::options_description _opt;
    
};
/*
 * class for icmp parameters
*/
class Icmp: public IpRule{
    
public:
    Icmp();
    explicit Icmp(const std::vector<std::string>& tkn_rule);
    void parse();
    bool check_packet(const void * hdr,
                      const uint32_t s_addr,
                      const uint32_t d_addr) const override;   
    NumComparable<uint8_t> type;
    NumComparable<uint8_t> code;
    boost::program_options::options_description _opt;
};
#endif /* IP_HPP */

