#include "sqlite.hpp"

namespace Sqlite{

using namespace std;


SQLite::SQLite(std::string tb):db("Tarodb.db"), tb_name(tb){

	db <<"PRAGMA foreign_keys=ON;";
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
}
unsigned int SQLite::get_last_id(){

	unsigned int id;
	std::string q = query[static_cast<int>(DB_Manual::ID_MAX)] + tb_name + " ;"; 

	try{
		db << q	 >> [&id](int _id) {id=std::move(_id);};
	}catch(std::exception& e){
		std::cerr<<e.what()<<std::endl;
		return -1;
	}

	return id;
}

bool SQLite::insert_record(std::string data,std::string thr,
	       	std::string stime, std::string stat){

	if(tb_name == "Taro" && thr!=""){
		std::string q = query[static_cast<int>(DB_Manual::INSERT_MAIN)];
		try{
			db<<"begin;";
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
bool SQLite::insert_record(int id, std::string data){

	if(tb_name == "Taro_Filter" && id>0 && data!=""){
		std::string q = query[static_cast<int>(DB_Manual::INSERT_FILTER)];
		try{
			db<<"begin;";
			db<<q <<id <<data;
			db<<"commit;";
		}catch(std::exception& e){
			std::cerr<<e.what()<<std::endl;
			return false;
		}
		return true;
	}
	return false;

}
bool SQLite::update_record(int id, unsigned int b, unsigned int p, std::string etime, std::string stat){

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
			db<< q.c_str() << id;
		}catch(std::exception &e){
			std::cerr<<e.what()<<std::endl;
			return false;
		}
		return true;
	}
	return false;

}
std::string SQLite::status(int id){

	if(tb_name == "Taro" && id>0){
		try{
			std::string result;
			db << query[static_cast<int>(DB_Manual::STATUS)] << id 
				>>[&result](std::string str){result = std::move(str);};
			return result;
		}catch(std::exception &e){
			std::cerr<< e.what()<<std::endl;
			return "";
		}
	}
	return "";
}
bool SQLite::status(std::string rule, std::string stat){

	if(tb_name == "Taro"){	
		try{		
			bool res=false;
			db<<query[static_cast<int>(DB_Manual::M_STATUS)]
				<<rule <<stat
				>>[&res](bool x){res=x;};
			return res;
		}catch(std::exception &e){
			std::cerr<< e.what()<<std::endl;
			return false;
		}
	}
	return false;
}
std::vector<std::string> SQLite::select_all_records(){

	std::vector<std::string> res;

	try{
		int x = (tb_name =="Taro")?static_cast<int>(DB_Manual::M_ALL):
			static_cast<int>(DB_Manual::F_ALL);
		std::string q = query[x]; 
		if(tb_name=="Taro"){
			db<<q >>[&](int id, std::string rule, std::string th,
					std::string b, std::string p, std::string st,
				      	std::string et, std::string s){
				std::string tmp = std::to_string(id) + " " +
					  rule  + " " + th + " " + b + " " + 
					  p + " " + st + " " + et + " " + s ;
				res.push_back(tmp);
			};
		}
		if(tb_name=="Taro_Filter"){
			db<<q >>[&](int id, std::string fil){
				std::string tmp = std::to_string(id) + " " +
					fil;
				res.push_back(tmp);

			};
		}

	}catch(std::exception& e){
		std::cerr<<e.what()<<std::endl;
		return {};
	}
	return res;

}

}

