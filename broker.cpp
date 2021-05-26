#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/util.h>

#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>

#include <iostream>
#include <vector>
#include <string>
#include <ctime>

#include <boost/program_options.hpp>
#include <boost/thread.hpp>

#include "filter/functions.hpp"
#include "filter/sqlite.hpp"
#include "filter/bgp.hpp"

#define MAX_LINE 256

using namespace BGP;
//bgp inventory map
std::map<uint32_t, unsigned int> bgp_inv;
boost::asio::io_context io_context_;
std::shared_ptr<Bgp> bgp;

void usage(void);
bool tcplisten(const char *,const char *, struct event_base *);
void read_cb(struct bufferevent *, void *);
void error_cb(struct bufferevent *, short, void *);
void accept_cb(evutil_socket_t, short, void *);
std::string not_in_db(const std::string&);
bool update_db(const std::string&, uint32_t&);
bool load_config(std::string&, std::string&);
bool db_pre_check();
std::string get_time();
/*
 * XXX action callbacks
 * ? void action_cb(char *);
 * ? void update_db(int, char*)
 * ...
 */
//defining database initialization
bool Sqlite::SQLite::conf = true;
bool Sqlite::SQLite::init_database = true ;

int
main(int argc, char **argv)
{
	std::string port{"9200"}, ip{"127.0.0.1"};
	int ch, dflag = 0;

	while ((ch = getopt(argc, argv, "dhp:")) != -1) {
		switch (ch) {
		case 'd':
			dflag = 1;
			break;
		case 'h':
			usage();
			return 1;
		case 'p':
			port = optarg;
			break;
		default:
		        usage();
		        return 1;
		}
	}
	if(!db_pre_check()){
		std::cerr<<"Couldn't Update database!"<<std::endl;
		return 1;
	}

	if(!load_config(port, ip)){
		std::cerr<<"Couldn't load config file!"<<std::endl;
		return 1;
	}
	/* daemonise */
	//if(!dflag)
	//	daemon(1, 0);
	
	setvbuf(stdout, NULL, _IONBF, 0);

	struct event_base *base;
	
	/*
	 * XXX event_base_new() returns NULL if it fails to return a
	 * new event. I am not sure if there is any better way to
	 * handle its failure - needs further investigation.
	 */
	base = event_base_new();
	if (!base) {
		fprintf(stderr, "event_base_new() failed to return");
		return 1;
	}

	tcplisten(port.c_str(), ip.c_str(),  base);
	
	return 0;
}
/* Update undone records*/
bool
db_pre_check(){

	using namespace Sqlite;
	SQLite sq("Taro");
	std::vector<int> res = sq.pre_check();
	for(auto id: res)
		if(!sq.update_record(id, 0, 0, get_time(), "DONE"))
			return false;

	return true;
}
/* Load config file for filter process*/
bool 
load_config(std::string& port, std::string& ip){
	
	const std::string config_file = "/etc/ddosdetector.conf";
	int bgpid =0,timeout =5, _port =0;
	std::string  iface ="", bpass="", enpass="", _ip ="";
	namespace po = boost::program_options;
	po::options_description config_file_opt("Configuration File");
	config_file_opt.add_options()
		("General.Bgp_Id", po::value<int>(&bgpid))
		("General.Interface", po::value<std::string>(&iface))
		("General.Timeout", po::value<int>(&timeout))
		("General.Bgp_Pass", po::value<std::string>(&bpass))
		("General.Enable_Pass", po::value<std::string>(&enpass))
		("General.Bgpd_Ip", po::value<std::string>(&_ip))
		("General.Bgpd_Port", po::value<int>(&_port))
		("Main.Main_Port", po::value<std::string>(&port))
		("Main.Main_IP", po::value<std::string>(&ip))
		;
	po::variables_map vm;
	try{
		std::ifstream cnf(config_file);
		if(cnf){
			po::store(po::parse_config_file(cnf, config_file_opt, true), vm);
			po::notify(vm);
		}
		else{
			std::cerr<<"Configuration file: " << config_file
				<< " not found"<<std::endl;
			return false;
		}
	}catch(po::error& e){
		std::cerr<<"Parse Options Error: " << e.what()
			<<std::endl<<std::endl;
		return false;
	}

        bgp = std::make_shared<Bgp>(io_context_, bpass, enpass, _ip, bgpid, _port);
	using namespace Sqlite;
	SQLite sq("Taro_Config");
	return sq.set_config(bgpid, iface, timeout, bpass, enpass, _ip, _port, ip, std::atoi(port.c_str()));
}
/*
 * XXX tcplisten() only listens on IPv4 at present and does no
 * resolve any hostname. It might be a good idea to use
 * evutil_getaddrinfo() from event2/util.h later.
 */
bool
tcplisten(const char *port, const char *ip, struct event_base *base)
{
	evutil_socket_t listener;
	struct sockaddr_in sin;
	struct in_addr saddr;
	struct event *listener_event;
	
	if(inet_pton(AF_INET, ip, &saddr) != 1){
		std::cerr<<"Coudn't bind to address " + std::string(ip)<<std::endl;
		return 1;
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = saddr.s_addr;
	sin.sin_port = htons(atoi(port));
	
	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	evutil_make_socket_nonblocking(listener);
	int opt = 1;

	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt,
				sizeof(int)) < 0)
		perror("setsockopt failed");
	
	if (bind(listener, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
		perror("bind");
		return 1;
	}
	
	if (listen(listener, 16) < 0) {
		perror("listen");
		return 1;
	}
	
	listener_event = event_new(base, listener, EV_READ | EV_PERSIST,
	   	    		 accept_cb, (void *)base);
	
	event_add(listener_event, NULL);
	
	event_base_dispatch(base);

	return 0;
}

void
usage(void)
{
	extern char *__progname;
	fprintf(stderr, "usage: %s [-d] [-p port]\n",
			__progname);
}
std::string
get_time(){
	auto t = std::time(0);
	auto tm = *localtime(&t);
	char buf[80];
	strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tm);
	return std::string(buf);

}
void
erase_garbage(std::vector<std::string>& r){

	std::vector<std::string>::iterator it = std::find(r.begin(), r.end(), "--bps-th-period");
	std::vector<std::string>::iterator e = it;
	++e; ++e;

	if(it != r.end())
		r.erase(it, e);

	it = std::find(r.begin(), r.end(), "--pps-th-period");
	e = it; ++e; ++e;
	if(it != r.end())
		r.erase(it, e);

	it = std::find(r.begin(), r.end(), "-c");
	e = it; ++e; ++e;
	if(it != r.end())
		r.erase(it, e);
}

std::string
not_in_db(const std::string& rule){

	std::vector<std::string> prs_rule = space_tokenize(rule);
	erase_garbage(prs_rule);

	std::vector<std::string>::iterator it = std::find(prs_rule.begin(), prs_rule.end(), "IP");
	std::vector<std::string>::iterator itt;
	std::string ip, tmp{}, dtmp{};

	if(it != prs_rule.end()){
		ip = *++it;
		it++;
		if(*it == "RULE"){
			itt = it;
			it = std::find(++it, prs_rule.end(), "-d");
			*++it = ip;
		}
	
		for(auto i = ++itt; i< std::find(itt, prs_rule.end(), "--filter");i++)
			dtmp+= (i != prs_rule.end())? (*i + " "): ("\n");

		using namespace Sqlite;
		SQLite sq("Taro");
		if(!sq.status(dtmp, "RUNNING")){
			if(!sq.insert_record(dtmp, "0", get_time() ,"RUNNING"))
				return "";

			for(auto i = itt; i<= prs_rule.end();i++)
				tmp+= (i != prs_rule.end())? (*i + " "): ("\n");

			int id = sq.get_last_id();
			dtmp = "ID " + std::to_string(id) + " " + tmp;
    			uint32_t dip = boost::asio::ip::make_address_v4(ip.substr(0, ip.find("/"))).to_ulong();
			bgp_inv[dip]++;
			std::cout<<ip<<" : "<<bgp_inv[dip]<<std::endl;
			return dtmp;
		}
		else
			return "";
	}
	else 
		return "";
}

void
read_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input, *output;
	char *line;
	size_t n;
	
	input = bufferevent_get_input(bev);
	output = bufferevent_get_output(bev);
	
	line = evbuffer_readln(input, &n, EVBUFFER_EOL_LF);
	
	char req_type[10];
	char *rules = (char *) ::operator new(strlen(line) + 1, std::nothrow); 
	std::sscanf(line, "%s %[^\t\n]", req_type, rules);
	/*
	 * Parse rules and act based on req_type[5]
	 */
	if (strcmp(req_type, "ANOMALY") == 0) {
		/* child mission */

		std::string prule;
		if((prule = not_in_db(rules)) != "" ){
			io_context_.notify_fork(boost::asio::execution_context::fork_prepare);
			if (fork() == 0)
			{
				io_context_.~io_context();
				if(fork() == 0 ){
					//daemon(1,0);
					
					int fd = open("/tmp",  O_EXCL | O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
					if(fd<0){
						std::cerr<<"Couldn't create process."<<std::endl;
						_exit(0);
					}
					write(fd, prule.c_str(), prule.size() + 1);
					lseek(fd,0,SEEK_SET);
					const char *argv[]={"Taro_Filter", std::to_string(fd).c_str(), NULL};
					execv("./Filter", (char * const *)argv);
				}
				else
					_exit(0);
			}else { /* parent mission */
				io_context_.notify_fork(boost::asio::io_context::fork_parent);
				evbuffer_add(output, "OK!\n", 5);
				wait(nullptr);
			}
		}
	}
	else if (strcmp(req_type, "FINISH") == 0) 
	{
		/* update databse */
		uint32_t ip;
		if(update_db(rules, ip))
		{
			//for incomplete process creation
			if(ip == 0)
				evbuffer_add(output, "OK!\n",5);

			bgp_inv[ip]--;
			if(bgp_inv[ip] == 0)
			{
				bgp_inv.erase(ip);
				for(;;)
				{
					 try
					 {
					    bgp->remove_announce(ip);
					    if(!bgp->status(ip))
						    break;
					 }catch(std::exception& e)
					 {
						std::cerr<<e.what()<<std::endl;
					 }
					 boost::this_thread::sleep_for(boost::chrono::milliseconds(100));
				}
			}
			evbuffer_add(output, "OK!\n",5);
		}
		else
			evbuffer_add(output, "WRONG!\n",8);
	}
	 else{
	 	//bufferevent_free(bev);
	  	evbuffer_add(output, "WRONG REQ!\n", 10);
	  }

	delete rules;
	free(line);
	// bufferevent_free(bev);
}
bool update_db(const std::string& data, uint32_t& ip_){

	std::vector<std::string> prs_data = space_tokenize(data);
	if(prs_data.size() >= 3){
		int id = std::atoi(prs_data[0].c_str());
		ip_ = std::atoi(prs_data[1].c_str());
		int bytes = std::atoi(prs_data[2].c_str());
		int packets = std::atoi(prs_data[3].c_str());

		for(unsigned int i=4; i< prs_data.size(); i++){
			try{
				Sqlite::SQLite df("Taro_Filter");
				if(!df.insert_record(id, prs_data[i])){
            				boost::this_thread::sleep_for(boost::chrono::milliseconds(10));
					continue;
				}
			}catch(...){
				continue;
			}

		}
		Sqlite::SQLite sq("Taro");
		return sq.update_record(id, bytes, packets, get_time(), "DONE");
	}
	return false;
}

void
error_cb(struct bufferevent *bev, short error, void *ctx)
{
	/* XXX - improve error handling */
//	if (error & BEV_EVENT_EOF)
//		perror("connection closed");
	if (error & BEV_EVENT_ERROR)
		perror(NULL);
	if (error & BEV_EVENT_TIMEOUT)
		perror("timed out");
	bufferevent_free(bev);
}

void
accept_cb(evutil_socket_t listener, short event, void *arg)
{
	struct event_base *base = static_cast<event_base *>(arg);
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	int fd = accept4(listener, (struct sockaddr*)&ss, &slen, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (fd < 0)
		perror("accept");
	else if (fd > FD_SETSIZE)
		close(fd);
	else {
		struct bufferevent *bev;
		evutil_make_socket_nonblocking(fd);
		bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
		bufferevent_setcb(bev, read_cb, NULL, error_cb, NULL);
		bufferevent_setwatermark(bev, EV_READ, 0, MAX_LINE);
		bufferevent_enable(bev, EV_READ | EV_WRITE);
	}
}

/* XXX function callbacks
 *void
 *func_cb(data_type rules, ...)
 *{
 *	expression ...
 *}
 */
