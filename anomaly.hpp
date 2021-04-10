#ifndef ANOMALY_HPP
#define ANOMALY_HPP

#include <iostream>
#include <memory>

#include "ip.hpp"
#include "monitor.hpp"
#include "parser.hpp"
#include "lib/queue.hpp"

class Anomaly{
    
public:
    
    Anomaly(uint8_t proto, std::shared_ptr<IpRule>& rl);
    Anomaly(const Anomaly & oth);
    Anomaly& operator +=(Anomaly & oth);
    Anomaly& operator =(Anomaly & oth);
    bool check_packet(const void * hdr,
                      const uint32_t s_addr,
                      const uint32_t d_addr,
                      const unsigned int len);
    void calc_data(const Anomaly& anom);
    void check_triggers(std::shared_ptr<ts_queue<token>> & l);
    void add_filter_rule(std::string str);
    
    
private:
    
    unsigned long int id;
    std::shared_ptr<IpRule>& rule_;
    Monitor monitor_;
    uint8_t proto_;
    
    
};

#endif
