#ifndef BGP_HPP
#define BGP_HPP

#include<iostream>
#include<string>
#include<vector>

#include<boost/asio/ip/address_v4.hpp>

#include "client.hpp"

namespace BGP{
/*
 * define static text for ADD/REMOVE advertising
*/
enum class Step : int {enable=0, configure=1, rtr=2, add=3 ,status=4};
const std::vector<std::string> cmd_  = { "enable\r\n", "conf t\r\n", "router bgp ", "network ", "show ip bgp " };
/*
 * class that is responsible for talking to bgpd process
*/
class Bgp: public Client{

public:

	explicit Bgp(boost::asio::io_context& io_context_, std::string& p, std::string& e_p, std::string& ip , unsigned int r_id,unsigned short port);
	explicit Bgp(boost::asio::io_context& io_context_, uint32_t dst_addr,std::string& p, std::string& e_p, std::string& ip , unsigned int r_id,unsigned short port);
	bool announce(uint32_t ip);
	bool announce();
	bool remove_announce(uint32_t ip);
	bool remove_announce();
	bool status(uint32_t ip);
	bool status();
private:

	bool login();
	bool send_request(uint32_t ip, const std::string& str);
	bool match_string(std::string, std::string);

	const std::string pass;
	const std::string enable_pass;
	const unsigned int rtr_id;
	const uint32_t dst_addr;

};
}
#endif
