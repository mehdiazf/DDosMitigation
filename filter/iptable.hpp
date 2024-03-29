#ifndef IPTABLE_HPP
#define IPTABLE_HPP

#define typeof(x) __typeof__(x)

extern "C"{
#include<libiptc/libiptc.h>
#include<xtables.h>
}
#include<arpa/inet.h>
#include<iostream>
#include<string>
#include<memory>
#include<errno.h>
#include<unistd.h>
#include<string.h>
#include<bitset>
#include<boost/program_options.hpp>
#include<math.h>

#include "monitor.hpp"
#include "ip.hpp"
#include "parser.hpp"

/*
 * a wrapper class around libiptc for ADD/DEL iptable rules based on token
*/
class Iptable{

public:
    explicit Iptable(const std::string& inface, const  std::string& id_, unsigned int pro, std::vector<std::string>& input );
    ~Iptable();
    bool  add_rule(token &t);
    bool remove_all();
    ipt_counters get_counters();

private:
    bool stat1;
    bool stat2;
    bool  add_chain();
    bool insert_rule(bool match_rule);	
    bool remove_chain();
    bool remove_pre_chain();
    bool remove_rule_chain();
    void clean_l3();
    void clean_tcp(struct ipt_tcp * tcp_);
    void clean_udp(struct ipt_udp * udp_);
    void clean_icmp(struct ipt_icmp * icmp_);
    void add_options(std::vector<std::string>&);
    bool set_tcp_field(token& t, struct ipt_tcp * tcp_);		
    bool set_udp_field(token& t, struct ipt_udp * udp_);		
    bool set_icmp_field(token& t, struct ipt_icmp * icmp_);		
    bool cut_match();
    bool append_match();
    bool set_chain_rule();
    bool return_rule();
    const std::string iface;
    const std::string table;
    const std::string id;
    const unsigned int proto;
    std::string chn_name;

    uint32_t dst_addr;
    NumRange<uint32_t> src_addr;
    NumRange<uint16_t> sport;
    NumRange<uint16_t> dport;
    std::pair<std::bitset<6>, std::bitset<6>> tcp_flgs;
    int8_t icmp_type;
    NumRange<uint8_t> icmp_code;

    struct xtc_handle * h;
    ipt_chainlabel chain;
    //these pointers are used for L4 rule
    struct ipt_entry * en;
    struct ipt_entry_match * m;
    struct ipt_entry_target  target;
    //structure for L3 rule
    struct Std_rule {
    	struct ipt_entry en;
    	struct xt_standard_target target;
    };
    Std_rule rl;     
    size_t m_size;
    boost::program_options::options_description _opt;
};
#endif
