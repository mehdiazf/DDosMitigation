#ifndef CPP_SQLITE_HPP
#define CPP_SQLITE_HPP

#include<iostream>
#include<algorithm>
#include<cctype>
#include<type_traits>
#include<functional>
#include<sqlite3.h>
#include<tuple>
#include<memory>
#include<string>

namespace sqlite{

	class binder;

	struct db_config{
		int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
		const char * zVfs = nullptr;
		int encoding = SQLITE_ANY;
	};
	template<typename> struct fucntion_trait;
	template<typename T>
		struct function_trait: public function_trait<decltype(&std::remove_reference<T>::type::operator())>{};

	template<typename CType, typename Ret, typename... Args>
		struct function_trait<Ret(CType::*)(Args...)> : function_trait<Ret(*)(Args...)>{};
	template<typename CType, typename Ret, typename... Args>
		struct function_trait<Ret(CType::*)(Args...) const> : function_trait<Ret(*)(Args...)>{}; //for lambda fucntions

	template<typename Ret, typename ...Args> 
		struct function_trait<Ret(*)(Args...)>{

			template<std::size_t Indx>
				using argument = typename std::tuple_element<Indx, std::tuple<Args...>>::type;
			static const std::size_t _size = sizeof...(Args);

		};

	template<std::size_t Count>
	class function_binder{

		public:
			template<typename Function, typename ...Values, std::size_t Boundry = Count>
				static typename std::enable_if<sizeof...(Values) < Boundry, void>::type f_binder(
						binder& db,
					        Function&& function,
						Values&&... values){
					typename std::remove_cv<typename std::remove_reference<
						typename function_trait<Function>::template argument<sizeof...(Values)>>::type>::type val{};

					db_get_col(db , sizeof...(Values), val);

					f_binder<Function>(db, function, std::forward<Values>(values)..., std::move(val));
					
				}
			template<typename Function, typename ...Values, std::size_t Boundry = Count>
				static typename std::enable_if<sizeof...(Values) == Boundry, void>::type f_binder(
						binder& db,
						Function&& function,
						Values&&... values){
					function(std::move(values)...);
				}


	};
	inline void except(const std::string& err){
		throw std::runtime_error("Error: " + err);
	}
	class binder{
		private:
			template<typename Type>
				struct is_sqlite_value : public std::integral_constant<bool, 
					std::is_integral<Type>::value ||
					std::is_floating_point<Type>::value ||
					std::is_same<std::string, Type>::value ||
					std::is_same<std::u16string, Type>::value ||
					std::is_same<sqlite_int64, Type>::value

				> {};
		public:
			binder() = delete;
			binder(const binder&) = delete;
			binder& operator=(const binder&) = delete;

			binder(std::shared_ptr<sqlite3> d, const std::string& qry)
				:_db(d), _stmt(sq_prepare(qry), sqlite3_finalize), _indx(0){}

			binder(binder&& oth):_db(std::move(oth._db)),_stmt(std::move(oth._stmt)),_indx(oth._indx){}
			~binder() noexcept(false){
				int res;
				while((res = sqlite3_step(_stmt.get())) == SQLITE_ROW) {}
				if(res != SQLITE_DONE)
					except(sqlite3_errstr(res));
			}

			sqlite3_stmt * sq_prepare(const std::string& q){
				sqlite3_stmt *st = nullptr;
				const char * rem;
				int res = sqlite3_prepare_v2(_db.get(), q.c_str(), -1, &st, &rem);
				if(res != SQLITE_OK)
					except(sqlite3_errstr(res));
				if(!std::all_of(rem, q.c_str() + q.size(), [](char ch){return isspace(ch);}))
					except(sqlite3_errstr(res));
				return st;
			}

			friend binder& operator <<(binder& db, const std::string& txt);
			friend binder& operator <<(binder& db, const int& val);
			friend binder& operator <<(binder& db, const sqlite3_int64& val);
			friend binder& operator <<(binder& db, const double& val);
			friend void db_get_col(binder& db, int indx, int& val);
			friend void db_get_col(binder& db, int indx, bool& val);
			friend void db_get_col(binder& db, int indx, double& val);
			friend void db_get_col(binder& db, int indx, std::string& val);


			template<typename Result>
				typename std::enable_if<is_sqlite_value<Result>::value, void>::type operator>>(Result& val){

					this->db_get_single_val([&val, this](){db_get_col(*this, 0, val);});
				}
			template<typename Function>
				typename std::enable_if<!is_sqlite_value<Function>::value, void>::type operator>>(Function&& func){
					this->db_get_vals([&func, this](){
							typedef function_trait<Function> trait;
							function_binder<trait::_size>::f_binder(*this, func);
							});
				}

		private:
			std::shared_ptr<sqlite3> _db;
			std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> _stmt;
			int _indx;

			void db_get_single_val(std::function<void(void)> call_back){
					get_indx();
					_indx=0;
					int res;
					if((res = sqlite3_step(_stmt.get())) == SQLITE_ROW)
						call_back();
					else if(res != SQLITE_DONE)
					        except(sqlite3_errstr(res));
			}
			void db_get_vals(std::function<void(void)> call_back){
					get_indx();
					_indx=0;
					int res;
					while((res = sqlite3_step(_stmt.get())) == SQLITE_ROW )
						call_back();
					if(res != SQLITE_DONE)
					        except(sqlite3_errstr(res));
			}
			int get_indx(){
				if(!_indx){
					sqlite3_reset(_stmt.get());
					sqlite3_clear_bindings(_stmt.get());
				}
				return ++_indx;
			}


	};

	class database{

		public:
			explicit  database(const std::string& name, const db_config& c={}):db(nullptr){
				sqlite3 * sq = nullptr;
				auto opn = sqlite3_open_v2(name.c_str(), &sq, static_cast<int>(c.flags), c.zVfs);
				db = std::shared_ptr<sqlite3>(sq, [](sqlite3 * ptr){sqlite3_close_v2(ptr);});
				if(opn != SQLITE_OK)
					throw std::runtime_error(db? std::to_string(sqlite3_extended_errcode(db.get())): std::to_string(opn));
			}
			
			binder operator<<(const std::string& query){
				return binder(db, query);
			}
			binder operator<<(const char * query ){
				return *this<<std::string(query);
			}

		private:
			
			std::shared_ptr<sqlite3> db;	

	};

	inline void db_get_col(binder& db, int indx, int& val){
		if(sqlite3_column_type(db._stmt.get(), indx) == SQLITE_NULL)
			val=0;
		else
			val = sqlite3_column_int(db._stmt.get(), indx);
	}
	inline void db_get_col(binder& db, int indx, bool& val){
		if(sqlite3_column_type(db._stmt.get(), indx) == SQLITE_NULL)
			val=0;
		else
			val = sqlite3_column_int(db._stmt.get(), indx);
	}
	inline void db_get_col(binder& db, int indx, double& val){
		if(sqlite3_column_type(db._stmt.get(), indx) == SQLITE_NULL)
			val=0;
		else
			val = sqlite3_column_double(db._stmt.get(), indx);
	}
	inline void db_get_col(binder& db, int indx, std::string& val){
		if(sqlite3_column_type(db._stmt.get(), indx) == SQLITE_NULL)
			val = std::string();
		else{
			sqlite3_column_bytes(db._stmt.get(), indx);
			val = std::string(reinterpret_cast<const char *>(sqlite3_column_text(db._stmt.get(),indx)));
		}
	}

	inline binder& operator<<(binder& db, const double& val){
		int res;
		if((res = sqlite3_bind_double(db._stmt.get(), db.get_indx(), val)) != SQLITE_OK )
			except(sqlite3_errstr(res));
		return db;
	}
	inline binder& operator<<(binder& db, const int& val){
		int res;
		if((res = sqlite3_bind_int(db._stmt.get(), db.get_indx(), val)) != SQLITE_OK )
			except(sqlite3_errstr(res));
		return db;
	}
	inline binder& operator<<(binder& db, const sqlite3_int64& val){
		int res;
		if((res = sqlite3_bind_int64(db._stmt.get(), db.get_indx(), val)) != SQLITE_OK )
			except(sqlite3_errstr(res));
		return db;
	}
	inline binder& operator<<(binder& db, const std::string& val){
		int res;
		if((res = sqlite3_bind_text(db._stmt.get(), db.get_indx(), val.c_str(), -1, SQLITE_TRANSIENT)) != SQLITE_OK )
			except(sqlite3_errstr(res));
		return db;
	}
	template<std::size_t N>
		inline binder& operator<<(binder& db, const char (&str)[N]){
			return db<< std::string(str);
		}
	template<typename T>
		binder&& operator<< (binder&& db, const T& val){db<<val; return std::move(db);}


}
#endif
