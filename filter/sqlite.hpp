#ifndef SQLITE__HPP
#define SQLITE__HPP
#include<iostream>
#include<tuple>

#include "../lib/cpp_sqlite.hpp"
namespace Sqlite{

using namespace sqlite;

enum class DB_Manual: int { ID_MAX=0, INSERT_FILTER=1, INSERT_MAIN=2, 
	UPDATE=3, STATUS=4, M_STATUS=5, M_ALL=6, F_ALL=7, GET_CONFIG=8, SET_CONFIG=9, UP_CONFIG=10, DEL_CONFIG=11, UNDONE=12};
const std::vector<std::string> query = {"select max(id) from ", 
	"insert into Taro_Filter (id,filter) values (?,?);",
	"insert into Taro (rule,threshold,bytes,packets,stime,etime,status) values (?,?,?,?,?,?,?);",
	"update Taro set ",
	"select status from Taro where id == ?;",
	"select exists(select id from Taro where rule == ? AND status == ?) ;",
	"select * from Taro ",
	"select * from Taro_Filter ",
	"select bgpid,interface,timeout,bgppass,enablepass,bgpdip,bgpdport,mainip,mainport from Taro_Config where id == 1;",
	"insert into Taro_Config (bgpid) values (?);",
	"update Taro_Config set ",
	"drop table if exists Taro_Config;",
	"select id from Taro where status == 'RUNNING';"

};
/*
 *This class is going to handle sqlite database
 the database has two tables including Taro and Taro_Filter.
 *Note. for difinition of an object of this type you should select the name of table palces in the database,
  which were defined as Taro and Taro_Filter
 table correspondingly.
 * */
class SQLite{

public:

	explicit SQLite(const std::string& tb);
	bool insert_record(const std::string& data, const std::string& thr="",
		       const std::string& stime="", const std::string& stat="") noexcept;
	bool insert_record(int id=-1 , const std::string& data="");
	bool update_record(int id=-1, unsigned int b=0, unsigned int p=0,
		       std::string etime="", std::string stat="") noexcept;
	//return status of given anomaly using id
	std::string status(int id=-1) noexcept; 
	//if this animaly considering ip,proto,stat exsit?
	bool status(const std::string& rule, const std::string& stat) noexcept;
	std::vector<std::string> select_all_records() noexcept;
	unsigned int get_last_id() noexcept;
	/* get config*/
	std::tuple<int, std::string, int,
		std::string, std::string,
		std::string, int, std::string, int> get_config();
	// when the main process spawn, it will update possible undone status
	std::vector<int> pre_check() noexcept;
	bool set_config(int bgpid, std::string& iface, int tout,
		    std::string& bpass, std::string& enpass,
		    std::string& bip, int port, std::string& mip, int mport ) noexcept;
	/* For initializing, as table has only one row for config*/
	static bool conf;
	static bool init_database;

private:
	database db;
	const std::string tb_name;
	bool create_conf_table();

};
}
#endif
