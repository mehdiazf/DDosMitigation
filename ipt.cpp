#include<iostream>

#include "iptable.hpp"
#include<unistd.h>

int main(){

	Iptable x("ens160"," 12334", 232435545 , 1 );
	token t(54543523,"src_ip");
	if(!x.add_rule(t))
		std::cout<<"couldnt create rule"<<std::endl;
}
