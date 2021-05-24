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
#define MAX 1000000

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

class token{
    
public:
    token():token(0, ""){}    
    token(uint32_t x, const std::string& y):val(x), type(y){}    
    token(const token& oth):val(oth.val), type(oth.type){}
    //token& operator=(const token& oth){val=oth.val; type=oth.type; return *this;}
    uint32_t val;    
    std::string type;
                    
};

/*class templatefilter{

public:
    templatefilter();
    templatefilter(std::string _type);
    bool _stat();
    virtual void increase(uint32_t ,const unsigned int ) =0;
    virtual void increase(uint16_t ,const unsigned int ) =0;
    virtual void increase(uint8_t ,const unsigned int ) =0;
    virtual void increase(std::string ,const unsigned int ) =0;
private:
    
    bool _enable;
    std::string type;

    
};
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
