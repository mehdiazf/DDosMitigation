#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "monitor.hpp"

//class Counter
Counter::Counter():count_packets(0),count_bytes(0),pps(0),bps(0){};    
Counter& Counter::operator=(const Counter& other){
    count_packets=other.count_packets;
    count_bytes=other.count_bytes;
    pps=other.pps;
    bps=other.bps;   
    return *this;
}
Counter::Counter(const Counter & other){
    
    count_packets=other.count_packets;
    count_bytes=other.count_bytes; 
    pps=other.pps;
    bps=other.bps;    
            
}

//class Filter
/*templatefilter::templatefilter():_enable(false),type(""){}
templatefilter::templatefilter(std::string _type):_enable(true),type(_type){}
bool templatefilter::_stat(){
    return _enable;
}*/
template <typename T>
Filter<T>::Filter():_enable(false),type(""),ratio(1){}
template <typename T>
Filter<T>::Filter(const Filter & f){
 
    filter_ = f.filter_;
    _enable = f._enable;
    ratio = f.ratio;
    type = f.type;
    last_update_ = f.last_update_;
    
}
template <typename T>
Filter<T>::Filter(std::string _type, unsigned int r):_enable(true),type(_type),
        ratio(r),last_update_(std::chrono::high_resolution_clock::now()),
        token_time_(std::chrono::high_resolution_clock::now()), delay_(2),
        sampling_(0,MAX), rnd_(1234){}
template <class T>
bool Filter<T>::_stat(){
    
    return _enable;
}
template <typename T>
void Filter<T>::increase(T val, const unsigned int len){

    filter_[val].count_packets++;
    filter_[val].count_bytes+=len;
}
template<typename T>
Filter<T>& Filter<T>::operator+=(Filter& oth){
        
    if(this !=  &oth)
    {
        for(auto& it: oth.filter_){
            filter_[it.first].count_bytes+=it.second.count_bytes;
            filter_[it.first].count_packets+=it.second.count_packets;                    
        }        
    oth.filter_.clear();
    last_update_ = std::chrono::high_resolution_clock::now();
    }
    return *this;
}
template<typename T>
Filter<T>& Filter<T>::operator=(Filter& oth){
    
    //filter_=oth.filter_;
    last_update_=oth.last_update_;
    oth.filter_.clear();	
    filter_.clear();	
    return *this;
    
}
template <typename T>
void Filter<T>::calc_data(const Filter& fil){
     //auto fil=const_cast<Filter<T>*>(fill);
 
    double delta_time;
    for(auto& it: filter_){
        delta_time = std::chrono::duration<double, std::milli>(
        last_update_ - fil.last_update_).count();
        it.second.pps= round(((it.second.count_packets)/delta_time)*1000);
        it.second.bps= round(((it.second.count_bytes )/delta_time)*1000);
    	//std::cout<<std::to_string(it.second.count_packets)
	//	<<":"<<delta_time<<":"<<std::to_string(it.second.pps)<<std::endl;
    }
    
}
template <typename T>
unsigned int Filter<T>::get_ratio(){
    return ratio;    
}
template <typename T>
std::string Filter<T>::get_info(uint32_t val){
    
    if(type == "src_ip" || type == "dst_ip")
        return type + " " + boost::asio::ip::address_v4(val).to_string();
    if(type == "src_port" || type == "dst_port")
        return type + " " + std::to_string(val);
    if(type == "icmp_type" || type == "icmp_code" )
        return type + " " + std::to_string(val);
    return " ";
            
}
template <typename T>
void Filter<T>::check_triggers(uint32_t _pps, uint32_t _bps, std::shared_ptr<ts_queue<token>> & l){
           
    auto _now = std::chrono::high_resolution_clock::now();
    auto diff = std::chrono::duration<double>(_now - token_time_).count();
    for(auto& it: filter_)
    {          
        if(_pps>0){            
            if(it.second.pps > (_pps*ratio)){                 
                if( diff > delay_ && (sampling_(rnd_)%2)==0)
                {                                                         
                    token_time_ = _now;
                    l->push(token(it.first, type));
                }
            }
        }
        else if(_bps>0){
            if(it.second.bps > (_bps*ratio)){                
                if( diff > delay_ && (sampling_(rnd_)%2)==0)
                {                     
                    token_time_ = _now;
                    l->push(token(it.first, type));
                }
            }   
        }        
    }
}
//class Monitor

Monitor::Monitor(uint8_t _proto): proto(_proto){}
Monitor::Monitor(const Monitor &oth){
    
    boost::lock(m_, oth.m_);
    boost::lock_guard<boost::shared_mutex> guard(m_, boost::adopt_lock);
    boost::lock_guard<boost::shared_mutex> oth_guard(oth.m_, boost::adopt_lock);
    proto = oth.proto;
    rule_.clear();
    for(auto& x: oth.rule_){        
        rule_.insert(make_filter(x.first, oth.proto, x.second->ratio));             
    }
        
}
void Monitor::calc_data(const Monitor &mon){
    
    if(this != &mon){
        boost::lock(m_, mon.m_);
        boost::lock_guard<boost::shared_mutex> guard(m_, boost::adopt_lock);
        boost::lock_guard<boost::shared_mutex> oth_guard(mon.m_, boost::adopt_lock);       
        for(auto& it: rule_){            
            it.second->calc_data(*mon.rule_.at(it.first));
        }
    }
    
}
void Monitor::check_triggers(uint32_t pps, uint32_t bps,std::shared_ptr<ts_queue<token>>& l){
 
    boost::lock_guard<boost::shared_mutex> guard(m_);
    for(auto& it: rule_){
        it.second->check_triggers(pps, bps, l);                
    }
    
}
void Monitor::add_rule(std::string _type, unsigned int r){
    
    auto it = rule_.find(_type);
    if( it == rule_.end())
        rule_.insert(make_filter(_type,proto,r));   
}
Monitor& Monitor::operator+=(Monitor& oth){
    
    if(this !=&oth){            
        boost::lock(m_, oth.m_);
        boost::lock_guard<boost::shared_mutex> guard(m_, boost::adopt_lock);
        boost::lock_guard<boost::shared_mutex> oth_guard(oth.m_, boost::adopt_lock);
        for(auto& it: oth.rule_){
            *rule_[it.first]+=*it.second;       
        }
    }
    return *this;
}
Monitor& Monitor::operator=(Monitor& oth){
    
    if(this != &oth){
        boost::lock(m_, oth.m_);
        boost::lock_guard<boost::shared_mutex> guard(m_, boost::adopt_lock);
        boost::lock_guard<boost::shared_mutex> oth_guard(oth.m_, boost::adopt_lock);        
        for(auto& it: oth.rule_){
            if(rule_.size() == oth.rule_.size()){
                *rule_[it.first]=*it.second;
            }
        }
      
    }
    return *this;
    
}
void Monitor::increase(const void* hdr, unsigned int len,
        const uint32_t s_addr, const uint32_t d_addr){
    
    boost::lock_guard<boost::shared_mutex> guard(m_);
    for(auto& it: rule_){
            
            if(it.first == "src_ip")
                it.second->increase(s_addr,len);
               
                
            if(it.first == "dst_ip")
                it.second->increase(d_addr,len);
               
                
            if(it.first == "country")
                break;
                ///future
            
            if(it.first == "src_port"){
                
                if(proto == 6){                    
                    auto tcp_hdr = (struct tcphdr *) hdr;
            #if defined (__FreeBSD__)
                    uint16_t h_sport = ntohs(tcp_hdr->th_sport);
            #elif defined(__linux__)
                    uint16_t h_sport = ntohs(tcp_hdr->source);
            #endif                            
                    it.second->increase(h_sport,len);
                }
                
                if(proto==17){
                    auto udp_hdr = (struct udphdr *) hdr;
            #if defined (__FreeBSD__)
                    uint16_t h_sport = ntohs(udp_hdr->uh_sport);
            #elif defined (__linux__)
                    uint16_t h_sport = ntohs(udp_hdr->source);
            #endif        
                    it.second->increase(h_sport,len);
                }
               
            }
                
            if(it.first == "dst_port"){
                
                if(proto == 6){    
                    auto tcp_hdr = (struct tcphdr *) hdr;
            #if defined (__FreeBSD__)
                    uint16_t h_dport = ntohs(tcp_hdr->th_dport);
            #elif defined(__linux__)
                    uint16_t h_dport = ntohs(tcp_hdr->dest);
            #endif        
                    it.second->increase(h_dport,len);
                }
                
                if(proto==17){
                    auto udp_hdr = (struct udphdr *) hdr;
            #if defined (__FreeBSD__)
                    uint16_t h_dport = ntohs(udp_hdr->uh_dport);
            #elif defined (__linux__)
                    uint16_t h_dport = ntohs(udp_hdr->dest);
            #endif        
                    it.second->increase(h_dport,len);
                }
                
            }
            
            ///ICMP  
            if(proto==1){
                auto icmp_hdr = (struct icmphdr *) hdr;
                if(it.first == "icmp_type"){
            #if defined (__FreeBSD__)
                    uint8_t h_type = icmp_hdr->icmp_type;
            #elif defined (__linux__)
                    uint8_t h_type = icmp_hdr->type;
            #endif    
                    it.second->increase(h_type,len);
                }
               
                if(it.first == "icmp_code"){
            #if defined (__FreeBSD__)
                    uint8_t h_code = icmp_hdr->icmp_code;
            #elif defined (__linux__)
                    uint8_t h_code = icmp_hdr->code;
            #endif
                    it.second->increase(h_code,len);
                }  
                
            }
            
                            
        }
        
    }

std::pair<std::string, std::unique_ptr<Filter<uint32_t>>> Monitor::make_filter(const std::string  _type , const uint8_t proto, unsigned int r){
    
    if( _type == "src_ip" || _type == "dst_ip")
        return std::make_pair(_type, std::make_unique<Filter<uint32_t>>(_type, r));
    if( (proto==6 || proto==17) && (_type == "src_port" || _type == "dst_port"))
        return std::make_pair(_type, std::make_unique<Filter<uint32_t>>(_type, r));
    if( proto==1 && (_type == "icmp_type" || _type == "icmp_code"))
        return std::make_pair(_type, std::make_unique<Filter<uint32_t>>(_type, r));

    return std::make_pair(_type, std::make_unique<Filter<uint32_t>>("src_ip", r));
}
    


template class Filter<uint32_t>;
//template class Filter<uint16_t>;
//template class Filter<uint8_t>;
//template class Filter<std::string>;

