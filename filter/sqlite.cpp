#include "sqlite.hpp"

namespace Sqlite{

using namespace std;

SQLite::SQLite(const std::string& tb):db("Tarodb.db"), tb_name(tb){

	if(init_database){
		db <<"PRAGMA foreign_keys=ON;";
		db <<"PRAGMA busy_timeout=30;";
		db <<
		"create table if not exists Taro ("
		"   id integer primary key autoincrement not null unique,"
		"   rule text not null,"
		"   threshold text not null,"
		"   bytes  int,"
		"   packets int,"
		"   stime text not null,"
		"   etime text not null,"
		"   status text not null"
		");";
		
		db <<
		"create table if not exists Taro_Filter ("
		"   id integer not null,"
		"   filter text,"
		"   foreign key(id) references Taro(id)"//on update action on delete action"
		");";
		SQLite::init_database = false;
		}
}
bool SQLite::create_conf_table(){
	
	db <<
	"create table if not exists Taro_Config ("
	"   id integer primary key autoincrement not null unique,"
	"   bgpid int not null,"
	"   interface text,"
	"   timeout  int,"
	"   bgppass text,"
	"   enablepass text,"
	"   bgpdip text,"
	"   bgpdport int,"
	"   mainip text,"
	"   mainport int"
	");";
	conf = false;
	return true;
}
unsigned int SQLite::get_last_id() noexcept{

	unsigned int id;
	std::string q = query[static_cast<int>(DB_Manual::ID_MAX)] + tb_name + " ;"; 

	try{
		db<<"BEGIN TRANSACTION;";
		db << q	 >> [&id](int _id) {id=std::move(_id);};
		db<<"commit;";
	}catch(std::exception& e){
		std::cerr<<e.what()<<std::endl;
		return -1;
	}

	return id;
}

bool SQLite::insert_record(const std::string& data, const std::string& thr,
	       	const std::string&  stime, const std::string& stat) noexcept{

	if(tb_name == "Taro" && thr!=""){
		std::string q = query[static_cast<int>(DB_Manual::INSERT_MAIN)];
		try{
			db<<"BEGIN IMMEDIATE TRANSACTION;";
			db<<q <<data <<thr <<0 <<0 <<stime <<0 <<stat;
			db<<"commit;";
		}catch(std::exception& e){
			std::cerr<<e.what()<<std::endl;
			return false;
		}
		return true;
	}
	return false;
}
bool SQLite::insert_record(int id, const std::string& data){

	if(tb_name == "Taro_Filter" && id>0 && data!=""){
		std::string q = query[static_cast<int>(DB_Manual::INSERT_FILTER)];
		try{
			db<<"BEGIN IMMEDIATE TRANSACTION;";
			db<<q <<id <<data;
			db<<"commit;";
		}catch(std::exception& e){
			throw;
		}
		return true;
	}
	return false;

}
bool SQLite::update_record(int id, unsigned int b, unsigned int p, std::string etime, std::string stat) noexcept{

	if(tb_name == "Taro" && id>0 && stat!=""){
		std::string format{};
		std::string q;
		if(b!=0){
			format+="bytes = '%u', packets = '%u', ";
		}
		format+="etime = '%s', status = '%s' where id == ?";

		if(b!=0){
			auto size = std::snprintf(nullptr, 0, format.c_str(), b, p, etime.c_str(), stat.c_str());
			std::string buf(size + 1 ,'\0');
			std::sprintf(&buf[0], format.c_str(), b, p, etime.c_str(), stat.c_str());
			q = query[static_cast<int>(DB_Manual::UPDATE)] + std::string(buf);
		}
		else{
			auto size = std::snprintf(nullptr, 0, format.c_str(), etime.c_str(), stat.c_str());
			std::string buf(size + 1 ,'\0');
			std::sprintf(&buf[0], format.c_str(), etime.c_str(), stat.c_str());
			q = query[static_cast<int>(DB_Manual::UPDATE)] + std::string(buf);
		}

		try{
			db<<"BEGIN IMMEDIATE TRANSACTION;";
			db<< q.c_str() << id;
			db<<"commit;";
		}catch(std::exception &e){
			std::cerr<<e.what()<<std::endl;
			return false;
		}
		return true;
	}
	return false;
}
std::string SQLite::status(int id) noexcept{

	if(tb_name == "Taro" && id>0){
		try{
			std::string result;
			db<<"BEGIN TRANSACTION;";
			db << query[static_cast<int>(DB_Manual::STATUS)] << id 
				>>[&result](std::string str){result = std::move(str);};
			db<<"commit;";
			return result;
		}catch(std::exception &e){
			std::cerr<< e.what()<<std::endl;
			return "";
		}
	}
	return "";
}
bool SQLite::status(const std::string& rule, const std::string& stat) noexcept{

	if(tb_name == "Taro"){	
		try{		
			bool res=false;
			db<<"BEGIN TRANSACTION;";
			db<<query[static_cast<int>(DB_Manual::M_STATUS)]
				<<rule <<stat
				>>[&res](bool x){res=x;};
			db<<"commit;";
			return res;
		}catch(std::exception &e){
			std::cerr<< e.what()<<std::endl;
			return false;
		}
	}
	return false;
}
bool SQLite::set_config(int bgpid, std::string& iface, int tout,std::string& bpass,
		std::string& enpass, std::string& bip, int port, std::string& mip, int mport) noexcept{

	if(conf){

		try{
			db<<query[static_cast<int>(DB_Manual::DEL_CONFIG)];
			create_conf_table();
			db<<query[static_cast<int>(DB_Manual::SET_CONFIG)]
				<< 0 ;
		}catch(std::exception& e){
			std::cerr<<e.what()<<std::endl;
			return false;
		}
	}
	std::string q = query[static_cast<int>(DB_Manual::UP_CONFIG)];
	q+= "bgpid = %d, interface = '%s', timeout = %d, bgppass = '%s', \
	       enablepass = '%s', bgpdip = '%s', bgpdport = %d, mainip = '%s' , mainport = %d where id == 1;";
			
	auto size = std::snprintf(nullptr, 0, q.c_str(), bgpid, iface.c_str(), tout, 
			bpass.c_str(), enpass.c_str(), bip.c_str(), port, mip.c_str(), mport);
	std::string buf(size + 1 ,'\0');
	std::sprintf(&buf[0], q.c_str(), bgpid, iface.c_str(), tout, 
			bpass.c_str(), enpass.c_str(), bip.c_str(), port, mip.c_str(), mport);

	try{
		db<<"BEGIN IMMEDIATE TRANSACTION;";
		db << buf.c_str();
		db<<"commit;";
	}catch(std::exception& e){
		std::cerr<<e.what()<<std::endl;
		return false;
	}

	return true;
}
std::tuple<int, std::string, int, std::string, std::string, std::string, int, std::string, int> SQLite::get_config(){

	std::string q = query[static_cast<int>(DB_Manual::GET_CONFIG)];
	int id, t, _port, mport;
	std::string _if, _pass, en_pass, _ip, mip;
	try{
		db<<"BEGIN TRANSACTION;";
		db<<q >>[&](int bid, std::string iface, int tout, std::string bpass,
			std::string epass, std::string ip, int port, std::string _mip, int _mport){
				id = bid; _if = iface; t = tout;
				_pass = bpass; en_pass = epass; 
				_ip = ip; _port = port; mip = _mip; mport = _mport;
			};
		db<<"commit;";
	}catch(std::exception& e){
		throw;
	}
	return {id, _if, t, _pass, en_pass, _ip, _port, mip, mport};
}
std::vector<int> SQLite::pre_check() noexcept{

	std::string q = query[static_cast<int>(DB_Manual::UNDONE)];
	std::vector<int> res;
	try{
		db<<"BEGIN TRANSACTION;";
		db<<q >>[&](int id_){
			res.push_back(id_);
		};
		db<<"commit;";
	}catch(std::exception& e){
		std::cerr<<e.what()<<std::endl;
		res.clear();
	}
	return res;
}
std::vector<std::string> SQLite::select_all_records() noexcept{

	std::vector<std::string> res;

	try{
		int x = (tb_name =="Taro")?static_cast<int>(DB_Manual::M_ALL):
			static_cast<int>(DB_Manual::F_ALL);
		std::string q = query[x]; 
		if(tb_name=="Taro"){
			db<<"BEGIN TRANSACTION;";
			db<<q >>[&](int id, std::string rule, std::string th,
					std::string b, std::string p, std::string st,
				      	std::string et, std::string s){
				std::string tmp = std::to_string(id) + " " +
					  rule  + " " + th + " " + b + " " + 
					  p + " " + st + " " + et + " " + s ;
				res.push_back(tmp);
			};
			db<<"commit;";
		}
		if(tb_name=="Taro_Filter"){
			db<<"BEGIN TRANSACTION;";
			db<<q >>[&](int id, std::string fil){
				std::string tmp = std::to_string(id) + " " +
					fil;
				res.push_back(tmp);

			};
			db<<"commit;";
		}

	}catch(std::exception& e){
		std::cerr<<e.what()<<std::endl;
		return {};
	}
	return res;
}

}

