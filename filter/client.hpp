#ifndef CLIENT_HPP
#define CLIENT_HPP


#include<iostream>
#include<string>
#include<vector>

#include<boost/asio/io_context.hpp>
#include<boost/asio/ip/tcp.hpp>
#include<boost/asio/write.hpp>
#include<boost/asio.hpp>
#include<boost/asio/ip/address_v4.hpp>

using boost::asio::ip::tcp;


class Client{

public:

	Client(std::string ip, unsigned short port);
	bool connect();
	void close();
	bool send(const std::string);
	std::string read(const std::string delim);

private:

	boost::asio::io_context io_context_;
	tcp::socket socket_;
	tcp::endpoint ep;
	unsigned short port;


};
#endif
