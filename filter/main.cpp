#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <algorithm>

#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<signal.h>
#include<ext/stdio_filebuf.h>

#include <boost/thread.hpp>
#include <boost/program_options.hpp>
#include <boost/asio.hpp>

#include "afsniff.hpp"
#include "anomaly.hpp"
#include "functions.hpp"
#include "../lib/queue.hpp"
#include "ip.hpp"
#include "iptable.hpp"
#include "sqlite.hpp"
#include "client.hpp"

#include<ctime>
#include<cstdlib>

#define END_PHRASE "FINISH"
bool Sqlite::SQLite::conf =0;

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
bool end_process(std::shared_ptr<Client>& _client, int id, int byte, int packet){

	if(!_client->connect())
		return false;
	std::string data = std::string(END_PHRASE) + " " + std::to_string(id) + 
		" " + std::to_string(byte) + " " + std::to_string(packet) + "\n";
	if(!_client->send(data))
		return false;
	if(_client->read("\n") == "OK!\n"){
		_client->close();
		return true;
	}
	return false;
}
void task_runner(std::shared_ptr<ts_queue<token>> task, int id, int timeout,
	       	uint8_t proto, uint32_t dst_addr, std::shared_ptr<Iptable>& ipt, std::shared_ptr<Client>& _client){

    std::chrono::high_resolution_clock::time_point _last = std::chrono::high_resolution_clock::now();
    std::chrono::high_resolution_clock::time_point _now;

    std::vector<std::string> rule_list;
    std::string str, data;
    using namespace Sqlite;
   
    SQLite df("Taro_Filter");
    for(;;)
    {
        boost::this_thread::interruption_point();
        token tmp;
	
	_now = std::chrono::high_resolution_clock::now();
	auto xx = std::chrono::duration<double>(_now - _last).count(); 
	std::cout<<xx<<std::endl;
	if( xx > timeout){
		struct ipt_counters x = ipt->get_counters();
		if(end_process(_client, id, x.bcnt, x.pcnt))
			kill(getpid(), SIGTERM);
	}

        if(task->wait_and_pop(tmp, 1000))
	{
		_last = _now;
		str = tmp.type + " " + std::to_string(tmp.val);
            	std::cout<<str<<std::endl;

		try
		{
			if(std::find( rule_list.begin(), rule_list.end(), str) == rule_list.end())
			{       
				if(tmp.type.find("ip") != std::string::npos)
					data = tmp.type + " " + boost::asio::ip::make_address_v4(tmp.val).to_string();
				else
					data = str;

				df.insert_record(id,data);
				ipt->add_rule(tmp);
				rule_list.push_back(str);
			}
		}catch(...)
		{
			continue;

		}
    
	}

   }

}

int main(int argc, char ** argv){
    
    if(argc >2 || argv[1]==NULL){
        std::cerr<<"Invalid argument."<<std::endl;
        return 1;
    }

   __gnu_cxx::stdio_filebuf<char> f(std::atoi(argv[1]), std::ios::in);
    std::istream is(&f);
    std::string line;
    std::getline(is, line);
    
    std::vector<std::string> input_p = space_tokenize(line);
    if(input_p.size()==0){
        std::cerr<<"Couldn't parse input."<<std::endl;
	return 1;
    }
    close(std::atoi(argv[1]));

   using namespace Sqlite;
   SQLite sq("Taro_Config");
   auto [bgpid, interface, timeout, bgppass, enable_pass, bgp_ip, bgp_port ] = sq.get_config();

    std::shared_ptr<Client> _client = std::make_shared<Client>("127.0.0.1", 9200);


    int id;//, timeout = 5;
    if(input_p[0] == "ID"){
	    id = std::atoi(input_p[1].c_str());
    }
    else
	throw std::invalid_argument("Invalid ID: " + input_p[1]);

    std::vector<std::string>::iterator b,e;
    b = input_p.begin();
    e = b; e++; e++;
    input_p.erase(b, e);

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
    boost::asio::io_service io_srv;
    boost::asio::signal_set signals(io_srv, SIGINT,SIGTERM);
    signals.async_wait(boost::bind(&boost::asio::io_service::stop, &io_srv));
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
    //std::string interface="ens160";   ///////////////////////should change in the future
    std::srand(std::time(nullptr));
   // int id = 1;// std::rand()%10000;
    std::shared_ptr<Iptable> iptable_ = std::make_shared<Iptable>(interface, std::to_string(id),proto_, input_p );
    AF_packet af_rcv(interface, threads, threads_anomly, *anomly, proto_);
    try{
        af_rcv.start();
    }
    catch(AfpacketException& e){
        std::cerr<<e.what()<<std::endl;
        return 1;        
    }
    
    threads.add_thread(new boost::thread(watcher, boost::ref(threads_anomly), anomly, task_list));
    threads.add_thread(new boost::thread(task_runner, task_list, id, timeout, proto_, rule->dst_addr, std::ref(iptable_), std::ref(_client)));


    //signals.async_wait([&threads,&io_srv](const boost::system::error_code& e
    //			    , int sn){threads.interrupt_all();io_srv.stop();});
    io_srv.run_one();
    threads.interrupt_all(); 
    threads.join_all();    

    //unlink(argv[1]);
    f.close();
   }
