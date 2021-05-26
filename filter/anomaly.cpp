#include "anomaly.hpp"

Anomaly::Anomaly(uint8_t proto, std::shared_ptr<IpRule> & rl)
	:rule_(rl),
        monitor_(proto),
	proto_(proto){}
Anomaly::Anomaly(const Anomaly & oth)
	:rule_(oth.rule_),
	monitor_(oth.monitor_),
	proto_(oth.proto_){}

Anomaly& Anomaly::operator+=(Anomaly& oth){
    
    if(this != &oth)
        monitor_+=oth.monitor_;       
    return *this;
}
Anomaly& Anomaly::operator=(Anomaly& oth){
   
    if(this != &oth)         
        monitor_=oth.monitor_;    
    return *this;
}
void Anomaly::calc_data(const Anomaly& anom){
    
    if(this != &anom){        
        monitor_.calc_data(anom.monitor_);        
    }
}
void Anomaly::check_triggers(std::shared_ptr<ts_queue<token>> & l){
    
    monitor_.check_triggers(rule_->pps_trigger, rule_->bps_trigger, l);
}
void Anomaly::add_filter_rule(const std::string& str){
    
    std::map<std::string, int> filter_map = filter_tokenize(str);  
    for(auto& o: filter_map){
        monitor_.add_rule(o.first, o.second);
	}   
}
bool Anomaly::check_packet(const void * hdr, const uint32_t s_addr,
                      const uint32_t d_addr, const unsigned int len){
    
    if(rule_->check_packet(hdr, s_addr, d_addr)){
        monitor_.increase(hdr,len,s_addr,d_addr);
        return true;
    }
    return false;    
}
