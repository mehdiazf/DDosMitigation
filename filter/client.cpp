#include "client.hpp"

Client::Client(boost::asio::io_context& io_context_, const std::string& ip, unsigned short port_)
	:socket_(io_context_),
	ep(boost::asio::ip::address::from_string(ip),port_),
	port(port_){}
//Client::~Client(){
//	close();
//}
bool Client::connect(){

	try{
		socket_.connect(ep);
	}catch(boost::system::system_error &e){
		std::cerr<<"Coudn't connect to port number("<<port <<") "
			<<e.what()<<std::endl;
	}
	return true;
}
void Client::close(){

	boost::system::error_code ec;
	socket_.close(ec);
	if (ec){
		throw std::runtime_error(ec.message());
	}
}
bool Client::send(const std::string& str){

	boost::system::error_code err;
	boost::asio::write(socket_, boost::asio::buffer(str), err );
	if(err){
		std::cerr<<err.message()<<std::endl;
		throw std::runtime_error("Conection failed.");
	}
	return true;
}
std::string Client::read(const std::string& delim){
		
	boost::system::error_code err;
	boost::asio::streambuf buf;
	boost::asio::read_until(socket_, buf, delim);
	return boost::asio::buffer_cast<const char*>(buf.data());
}
