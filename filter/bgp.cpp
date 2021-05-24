#include "bgp.hpp"

namespace BGP{

Bgp::Bgp(boost::asio::io_context& io_context_, std::string& p, std::string& e_p ,std::string& ip_, unsigned int r_id,unsigned short port_):
	Bgp(io_context_,0,p, e_p, ip_, r_id, port_){}
Bgp::Bgp(boost::asio::io_context& io_context_, uint32_t ip, std::string& p, std::string& e_p ,std::string& ip_, unsigned int r_id,unsigned short port_):
	Client(io_context_ ,ip_, port_),
	pass(p + "\r\n"),
       	enable_pass(e_p + "\r\n"),
       	rtr_id(r_id),
       	dst_addr(ip){}
bool Bgp::remove_announce(uint32_t ip){
	
	if(ip!=0)
	  	return send_request(ip, "no ");
	return false;
}
bool Bgp::remove_announce(){
	return remove_announce(dst_addr);
}
bool Bgp::announce(uint32_t ip){
	
	if(ip!=0)
		return send_request(ip, "");
	return false;
}
bool Bgp::announce(){
	return announce(dst_addr);
}
bool Bgp::match_string(std::string str, std::string known){

	std::string tmp = str.substr(str.find("\r\n")); 
	std::stringstream x(tmp); std::getline(x, tmp);
	std::getline(x, tmp);
	return tmp.compare(0, known.size(), known);

}
bool Bgp::status(){
	return status(dst_addr);
}
bool Bgp::status(uint32_t ip){	//if ip exist in bgp announcement
	
	if(!login())
		return false;

	std::string stat = cmd_[static_cast<int>(Step::status)] + 
		boost::asio::ip::make_address_v4(ip).to_string() + "/32\r\n";
	if(!send(stat))
		return false;
	std::string receive = read("\n");
	std::string rgx("% Network not in table");

	close();
	return match_string(receive, rgx);


}
bool Bgp::login(){

	if(!connect())
		return false;
	std::string receive = read("\n");

	if(!send(pass))		//send password
		return false;
	receive = read("> \r\n");
	
	if(!send(cmd_[static_cast<int>(Step::enable)]))  //send enable
		return false;
	receive = read("\n");
	
	if(enable_pass !="")
		if(!send(enable_pass))	//send enable pass if exist
			return false;
	receive = read("\n");

	return true;
}
bool Bgp::send_request(uint32_t ip, const std::string& str){

	if(!login())
		return false;

	if(!send(cmd_[static_cast<int>(Step::configure)]))	
		return false;
	std::string receive = read("\n");
	
	std::string rtr_cmd = cmd_[static_cast<int>(Step::rtr)] + std::to_string(rtr_id) + "\r\n";
	if(!send(rtr_cmd))	// adding ip to advertising list
		return false;
	receive = read("\n");

	std::string net_cmd = str + cmd_[static_cast<int>(Step::add)] + 
		boost::asio::ip::make_address_v4(ip).to_string() + "/32\r\n";
	if(!send(net_cmd))
		return false;
	receive = read("\n");
	close();
	return true;
}

}
