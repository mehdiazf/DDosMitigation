#ifndef MONITOR_HPP
#define MONITOR_HPP

#include <iostream>
#include <memory>
#include <chrono>
#include <map>
#include <math.h>
#include <vector>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <random>
#include <boost/thread.hpp>
#include <boost/chrono.hpp>
#include <boost/asio/ip/address_v4.hpp>

#include "../lib/queue.hpp"
//max number for selecting random trigger, avoiding queue clogging
#define MAX 1000000

/*
 * class that holds packet/byte counter
*/
class Counter
{
 public:
    Counter();
    Counter(const Counter& other);
    Counter& operator=(const Counter& other);
    uint64_t count_packets;
    uint64_t count_bytes;
    uint64_t pps;
    uint64_t bps;    
    
};
/*
 * class for triggering action (blocking)
*/
class token{
    
public:
    token():token(0, ""){}    
    token(uint32_t x, const std::string& y):val(x), type(y){}    
    token(const token& oth):val(oth.val), type(oth.type){}
    //token& operator=(const token& oth){val=oth.val; type=oth.type; return *this;}
    uint32_t val;    
    std::string type;
};
/*
 * class that holds data for each type of blocking for example for src_ip,
 * caculate threshold and generate token for iptable
 * @param: filter_: a map which holds counter for each type of blocking item
 *
*/
template<typename T>
class Filter  {
  
public:
    Filter();
    Filter(const Filter& f);
    Filter(const std::string& _type, unsigned int r);
    Filter& operator+=(Filter& oth);
    Filter& operator=(Filter& oth);
    bool _stat();
    void increase(T val, const unsigned int len);
    void calc_data(const Filter& fil);
    void check_triggers(uint32_t pps, uint32_t bps, std::shared_ptr<ts_queue<token>>& l);
    unsigned int get_ratio();
    std::string get_info(uint32_t val);

    bool _enable;
    std::string type;
    unsigned int ratio;
    std::chrono::high_resolution_clock::time_point last_update_;
    std::chrono::high_resolution_clock::time_point token_time_;
    unsigned int delay_;
    std::uniform_int_distribution<int> sampling_;
    std::default_random_engine rnd_;    
private:
    std::map<T,Counter> filter_;
    
};
/*
 * class that holds all kinds of blocking option including: src_ip, src_port, dst_ip, dst_port, icmp_type and icmp_code
 * @param: rule_: a map of blocking option and its corresponding filter
*/
class Monitor {
    
public:   
    Monitor(uint8_t _proto);
    Monitor(const Monitor &oth);
    Monitor& operator+=(Monitor& oth);
    Monitor& operator=(Monitor& oth);
    void calc_data(const Monitor& mon);
    void add_rule(std::string _type, unsigned int r);
    void increase(const void * hdr, unsigned int len, 
        const uint32_t s_addr, const uint32_t d_addr);    
    void check_triggers(uint32_t pps, uint32_t bps, std::shared_ptr<ts_queue<token>>& l);
    std::pair<std::string, std::unique_ptr<Filter<uint32_t>>> make_filter(const std::string  _type, const uint8_t proto, unsigned int r);
    
    
private:
    mutable boost::shared_mutex m_;
    std::map<std::string, std::unique_ptr<Filter<uint32_t>>> rule_;
    uint8_t proto;
};
#endif
