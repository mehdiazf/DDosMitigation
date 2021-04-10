#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <algorithm>

#include <boost/thread.hpp>
#include <boost/program_options.hpp>
#include <boost/asio.hpp>

#include "afsniff.hpp"
#include "ip.hpp"
#include "anomaly.hpp"
#include "functions.hpp"
#include "lib/queue.hpp"


void watcher(std::vector<std::shared_ptr<Anomaly>> & threads_collect,
        std::shared_ptr<Anomaly> anomly, std::shared_ptr<ts_queue<token>> task){

    Anomaly prev_anom(*anomly);
    uint8_t first_time =1;       
    for(;;)
    {
        
        for(auto& tc: threads_collect)
        {
	    
            *anomly+=*tc;                     	   
        }                        
        if(!first_time)
        {            
            anomly->calc_data(prev_anom);
            anomly->check_triggers(task);
            prev_anom=*anomly;	   
            
        }
        else
            first_time=0;
        boost::this_thread::sleep_for(boost::chrono::milliseconds(1000));
    }
    
}
void task_runner(std::shared_ptr<ts_queue<token>> task, uint8_t proto, uint32_t dst_addr){
                 
    for(;;)
    {
        boost::this_thread::interruption_point();
        token tmp;
        if(task->wait_and_pop(tmp, 1000))
            std::cout<<tmp.type<<":"<<std::to_string(tmp.val)<<std::endl;
            
    }
    
}

int main(int argc, char ** argv){
    
    if(argc >2 || argv[1]==NULL){
        std::cerr<<"Invalid argument."<<std::endl;
        return 1;
    }
    
    std::ifstream f(argv[1], std::ifstream::in);
    std::string line;
    
    if(f.is_open()){    
    std::getline(f, line);
    }
    else
    {
        std::cerr<<"Couldn't open file "<<argv[1]<<std::endl;
    }
    
    std::vector<std::string> input_p = space_tokenize(line);
    if(input_p.size()==0)
        std::cerr<<"Couldn't parse input."<<std::endl;
    
    std::string _proto = input_p[0];
    input_p.erase(input_p.begin());
    if(_proto != "ICMP" && _proto != "TCP" && _proto != "UDP" ){       
        std::cerr<<"Invalid protocol: "<<_proto<<std::endl;
        return 1;
	}
        
    std::string filter;
    for(std::vector<std::string>::iterator it = (input_p.begin()); it!=input_p.end();it++)
        if(*it == "--filter"){
            std::vector<std::string>::iterator tmp = it;
            filter = *(++it);            
            input_p.erase(tmp);
            input_p.erase(++tmp);
            break;
        }
    std::shared_ptr<IpRule> rule;
    boost::thread_group threads;
    uint8_t proto_;
    try{
        if(_proto == "TCP"){
            proto_=6;
            rule = std::make_shared<Tcp>(input_p);
        }            
        
        if(_proto == "UDP"){
            proto_=17;
            rule = std::make_shared<Udp>(input_p);
        }
       
        if(_proto == "ICMP"){
            proto_=1;
            rule = std::make_shared<Icmp>(input_p);
        }
           
       rule->parse();     
        
    }
    catch (ParserException& e){
        std::cerr<<e.what()<<std::endl;
        return 1;
    }
    
    std::vector<std::shared_ptr<Anomaly>> threads_anomly;
    auto anomly = std::make_shared<Anomaly>(proto_, rule);
    auto  task_list = std::make_shared<ts_queue<token>>();
    try{
        anomly->add_filter_rule(filter);
    }
    catch(ParserException& e){
        std::cerr<<e.what()<<std::endl;
        return 1;
    }
    std::string interface="ens160";   ///////////////////////should change in the future
    AF_packet af_rcv(interface, threads, threads_anomly, *anomly, proto_);
    try{
        af_rcv.start();
    }
    catch(AfpacketException& e){
        std::cerr<<e.what()<<std::endl;
        return 1;        
    }
    
    threads.add_thread(new boost::thread(watcher, std::ref(threads_anomly), anomly, task_list));
    threads.add_thread(new boost::thread(task_runner, task_list, proto_, rule->dst_addr));
    
    //threads.interrupt_all(); 
    threads.join_all();    

    //unlink(argv[1]);
    f.close();
    
    
   }
   
