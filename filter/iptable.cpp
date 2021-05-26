#include "iptable.hpp"
Iptable::~Iptable(){

	if(en !=NULL && stat1 && stat2){
		delete en; delete m;
	}
}
bool Iptable::remove_pre_chain(){

	rl.en.ip.src.s_addr = 0;
        rl.en.ip.smsk.s_addr = 0x0;
	const struct ipt_entry *e;
	int i;
	const char * t = table.c_str();
	const std::string pre("PREROUTING");

	if(!stat1){
		h= iptc_init(t);	
		if(h!=nullptr){
			for(e = iptc_first_rule(pre.c_str(), h), i =0; e; e = iptc_next_rule(e, h), i++ ){
				if(chn_name == static_cast<std::string>(iptc_get_target(e, h)))
					break;
			}

			stat1 = iptc_delete_num_entry(pre.c_str(), i, h);
			if(stat1)
				stat1 = iptc_commit(h);
			iptc_free(h);
		}
	}
	return stat1;
}
bool Iptable::remove_rule_chain(){

	const char * t = table.c_str();
	bool x = false;
	h = iptc_init(t);
	if(h!=nullptr){
		iptc_flush_entries(chain,h);
		x = iptc_commit(h);
		iptc_free(h);
	}
	return x;
}
bool Iptable::remove_chain(){

	remove_rule_chain();
	const char * t = table.c_str();
	if(!stat2){
		h = iptc_init(t);
		if(h!=nullptr){
			stat2 = iptc_delete_chain(chain,h);
			if(stat2)
				stat2 = iptc_commit(h);
			iptc_free(h);
		}
	}
	return stat2;
}
bool Iptable::remove_all(){

	remove_pre_chain();
	remove_chain();
	return (stat1 && stat2);

}
Iptable::Iptable(const std::string& inface, const std::string& id_, unsigned int prot_, std::vector<std::string>& input)
	: stat1(true), stat2(true),
	  iface(inface),
	  table("raw"),
	  id(id_),
	  proto(prot_),
	  chn_name("ANOMALY__"), 
	  tcp_flgs(std::make_pair(0x0, 0x0)),
	  icmp_type(-1)	
{
	add_options(input);
	chn_name.append(id);
	strncpy(chain, chn_name.c_str(), chn_name.size() );
	
	add_chain();
   	memset(&rl.en, 0, sizeof(rl.en));
        rl.en.ip.dst.s_addr = 0;
        rl.en.ip.dmsk.s_addr = 0x0;
        rl.en.ip.proto = proto;
        strncpy(rl.en.ip.iniface, iface.c_str(), IFNAMSIZ);
	m_size =0;
        if(proto == IPPROTO_TCP){
		m_size = XT_ALIGN(sizeof(*m)) + XT_ALIGN(sizeof(struct ipt_tcp));
		m = (struct ipt_entry_match *) ::operator new(m_size, std::nothrow);
		strncpy(m->u.user.name, "tcp", IPT_FUNCTION_MAXNAMELEN);
	}
        else if(proto == IPPROTO_UDP){
		m_size = XT_ALIGN(sizeof(*m)) + XT_ALIGN(sizeof(struct ipt_udp));
		m = (struct ipt_entry_match *) ::operator new (m_size, std::nothrow) ;
		strncpy(m->u.user.name, "udp", IPT_FUNCTION_MAXNAMELEN);
	}
        else if(proto == IPPROTO_ICMP){
		m_size = XT_ALIGN(sizeof(*m)) + XT_ALIGN(sizeof(struct ipt_icmp)); 	
		m = (struct ipt_entry_match *) ::operator new(m_size, std::nothrow);
		strncpy(m->u.user.name, "icmp", IPT_FUNCTION_MAXNAMELEN);
	}
	else{
		remove_all();
		throw std::runtime_error("protocol is not vaild.");
	}

	if(m_size != 0 && m != NULL ){
		m->u.match_size = m_size;
        	size_t size = XT_ALIGN(sizeof(struct ipt_entry_target)) + XT_ALIGN(sizeof (int));
        	target.u.user.target_size = size;
       	        strncpy(target.u.user.name, IPTC_LABEL_DROP, IPT_FUNCTION_MAXNAMELEN);
		en = (struct ipt_entry *) ::operator new(sizeof(*en ) + m_size + target.u.target_size, std::nothrow);
		//en = (struct ipt_entry *) calloc(1, sizeof(*en ) + m_size + target.u.target_size);
		if(en == NULL) 
			     throw std::runtime_error("Couldn't initialize iptables entry.");
		memset(en, 0, sizeof(struct ipt_entry));
   	        en->ip.dst.s_addr = dst_addr;
        	en->ip.dmsk.s_addr = 0xFFFFFFFF;
        	en->ip.proto = proto;
        	strncpy(en->ip.iniface, iface.c_str(), IFNAMSIZ);
		memcpy(en->elems + m->u.match_size, &target, target.u.target_size);
        	en->target_offset = sizeof(*en) + m->u.match_size;
        	en->next_offset = sizeof(*en) + m->u.match_size + target.u.target_size;

		rl.target.target.u.user.target_size = XT_ALIGN(sizeof (struct xt_standard_target)) ;
		rl.en.target_offset = sizeof (struct ipt_entry);
		rl.en.next_offset = rl.en.target_offset + rl.target.target.u.user.target_size;
		rl.en.nfcache |= NFC_IP_DST_PT;
		set_chain_rule();

	}
	else{
		remove_all();
		throw std::runtime_error("Couldn't initialize iptables entry.");
	}
}
void Iptable::add_options(std::vector<std::string> & in){
	
	namespace po = boost::program_options;
	_opt.add_options()
		("dstip,d", po::value<std::string>(), "destination ip address/net")
		("srcip,s", po::value<std::string>(), "source ip address/net")
		("dport", po::value<std::string>(), "destination port")
		("sport", po::value<std::string>(), "source port")
		("tcp-flag", po::value<std::string>(), "TCP flags <flag>:<enable>, where <enable> - 1 or 0; <flag> - U or R or P or S or A or F.")
		("type", po::value<std::string>(), "check if ICMP packet type = or > or < arg")
                ("code", po::value<std::string>(), "check if ICMP packet code = or > or < arg")
                ("bps-th", po::value<std::string>(), "check if ICMP packet code = or > or < arg")
                ("pps-th", po::value<std::string>(), "check if ICMP packet code = or > or < arg")
	;	
	parser::CommandParser cp(_opt);
	boost::program_options::variables_map vm = cp.parse(in);

	if(vm.count("dstip")){
		std::pair<uint32_t, uint32_t> tmp = parser::range_from_ip_string(vm["dstip"].as<std::string>()); 
		dst_addr = htonl(tmp.first);	
	}
	if (vm.count("srcip")) {
		src_addr = parser::range_from_ip_string(vm["srcip"].as<std::string>());
	}
	if (vm.count("dport")) {
		dport = parser::range_from_port_string(vm["dport"].as<std::string>());
	}
	if (vm.count("sport")) {
		sport = parser::range_from_port_string(vm["sport"].as<std::string>());		     
	}
	if (vm.count("tcp-flag")) {
		std::string flag_opt = vm["tcp-flag"].as<std::string>();
		tcp_flgs = parser::bitset_from_string<std::bitset<6>>(flag_opt,tcprule::accept_tcp_flags);	    
	}
	if (vm.count("type")) {
		std::pair<int8_t, unsigned short int> tmp = parser::numcomp_from_string<int8_t>(vm["type"].as<std::string>());
		if(tmp.second == 0)
			icmp_type = tmp.first; 
	}
	if (vm.count("code")) {
		icmp_code = parser::icmp_range(vm["code"].as<std::string>());
	}
}
bool Iptable::add_chain(){

	const char * t = table.c_str();
	h = iptc_init(t);
	if(!h)
	    throw std::bad_exception();

	if(!iptc_create_chain(chain,h)){
		iptc_free(h);
		throw std::runtime_error(iptc_strerror(errno));		
	}

        if(!iptc_commit(h)){
		iptc_free(h);
                throw std::runtime_error(iptc_strerror(errno));
	}
	iptc_free(h);
	stat2 = false;
	return true;	
}
bool Iptable::set_chain_rule(){

	if(!return_rule())
		return false;

	const char * tt = table.c_str();
        h = iptc_init(tt);
	rl.en.ip.dst.s_addr = dst_addr;
	rl.en.ip.dmsk.s_addr = 0xFFFFFFFF;
	strncpy(rl.target.target.u.user.name, chn_name.c_str(), IPT_FUNCTION_MAXNAMELEN); 
	int c = iptc_append_entry("PREROUTING", &rl.en, h);
	if(!c ){   
                iptc_free(h);
		remove_all();
                throw std::runtime_error(iptc_strerror(errno));
        } 
	int  x =iptc_commit(h);
	if(!x){
		iptc_free(h);
		remove_all();
            	throw std::runtime_error(iptc_strerror(errno));
	}	
	iptc_free(h);
	strncpy(rl.target.target.u.user.name, IPTC_LABEL_DROP, IPT_FUNCTION_MAXNAMELEN); 
	stat1 = false; //when delete entry
	return x;
}
ipt_counters Iptable::get_counters(){

	const char * tt = table.c_str();
        h = iptc_init(tt);
	const std::string pre("PREROUTING");
	const struct ipt_entry *e;
	int i;
	
	for(e = iptc_first_rule(pre.c_str(), h), i =0; e; e = iptc_next_rule(e, h), i++ ){
		if(chn_name == static_cast<std::string>(iptc_get_target(e, h)))
			break;
	}
	
	struct ipt_counters res{e->counters.bcnt, e->counters.pcnt};
	iptc_free(h);
	return res;
}
bool Iptable::return_rule(){
	
	const char * tt = table.c_str();
        h = iptc_init(tt);
	strncpy(rl.target.target.u.user.name, IPTC_LABEL_RETURN, IPT_FUNCTION_MAXNAMELEN);
	int c = iptc_append_entry(chain, &rl.en, h);
	if(!c ){   
                iptc_free(h);
		remove_all();
                throw std::runtime_error(iptc_strerror(errno));
        } 
	int  x =iptc_commit(h);
	if(!x){
		iptc_free(h);
		remove_all();
            	throw std::runtime_error(iptc_strerror(errno));
	}	
	iptc_free(h);
	return x;
}
bool Iptable::insert_rule(bool match_rule){
	
	int c=1;

	if(match_rule){
		c = iptc_insert_entry(chain, en, 0, h);
	}
	else{
		c = iptc_insert_entry(chain, &rl.en, 0, h);
	}
	if(!c ){   
                iptc_free(h);
                throw std::runtime_error(iptc_strerror(errno));
        } 
	int  x =iptc_commit(h);
	if(!x){
		iptc_free(h);
            	throw std::runtime_error(iptc_strerror(errno));
	}	
	iptc_free(h);
	return x;
}
void Iptable::clean_l3()
{
        en->nfcache &= (~NFC_IP_SRC_PT | ~NFC_IP_DST_PT);
        rl.en.nfcache &= (~NFC_IP_SRC_PT | ~NFC_IP_DST_PT);		
	if(src_addr.stat()){	
                en->ip.src.s_addr = rl.en.ip.src.s_addr = htonl(src_addr.start_);
		uint32_t dif = src_addr.end_ - src_addr.start_ ;
                en->ip.smsk.s_addr = rl.en.ip.smsk.s_addr =  static_cast<unsigned int>(pow(2, 32 - ceil(log(dif)/log(2))) - 1 );
	}else{
		en->ip.src.s_addr = rl.en.ip.src.s_addr = 0;
                en->ip.smsk.s_addr = rl.en.ip.smsk.s_addr = 0x0;
	}
}
void Iptable::clean_tcp(struct ipt_tcp * tcp_){
	
	if(sport.stat()){
		tcp_->spts[0] = sport.start_;
		tcp_->spts[1] = sport.end_;
	}else{
		tcp_->spts[0] = 0;
		tcp_->spts[1] = 0XFFFF;
	}
	if(dport.stat()){

        	tcp_->dpts[0] = dport.start_;
		tcp_->dpts[1] = dport.end_;                
	}else{

        	tcp_->dpts[0] = 0;
		tcp_->dpts[1] = 0xFFFF;                
	}
	if(tcp_flgs.first.to_string() != "000000"){
		auto reverse = [](uint16_t x){uint16_t r=0,n=6; while(n>0){r<<=1; if(x&1)r^=1; x>>=1;n--;} return r; };
		tcp_->flg_mask = reverse(tcp_flgs.second.to_ulong());
		tcp_->flg_cmp =  reverse(tcp_flgs.first.to_ulong());
	}else{		
		tcp_->flg_mask = 0;
		tcp_->flg_cmp = 0;
	}
}
void Iptable::clean_udp(struct ipt_udp * udp_){

	if(sport.stat()){
		udp_->spts[0] = sport.start_;
		udp_->spts[1] = sport.end_;
	}else{
		udp_->spts[0] = 0;
		udp_->spts[1] = 0XFFFF;
	}
	if(dport.stat()){

        	udp_->dpts[0] = dport.start_;
		udp_->dpts[1] = dport.end_;                
	}else{

        	udp_->dpts[0] = 0;
		udp_->dpts[1] = 0xFFFF;                
	}
}
void Iptable::clean_icmp(struct ipt_icmp * icmp_){
	
	if(static_cast<int>(icmp_type)>=0){
		icmp_->type = static_cast<int>(icmp_type);
		icmp_->code[0] = 0;
		icmp_->code[1] = 0xFF;
	}
}
bool Iptable::set_tcp_field(token& t, struct ipt_tcp * tcp_){

	clean_tcp(tcp_);

 	if(t.type == "dst_ip"){
                en->nfcache |= NFC_IP_DST_PT;
		return append_match();
        }
	else if(t.type == "src_ip"){
                en->ip.src.s_addr = htonl(t.val);
                en->ip.smsk.s_addr = 0xFFFFFFFF;
                en->nfcache |= NFC_IP_SRC_PT;
		return append_match();
        }
	else if(t.type == "src_port"){
        	tcp_->spts[0] = tcp_->spts[1] = t.val;
		return append_match();
        }
        else if(t.type == "dst_port"){
        	tcp_->dpts[0] = tcp_->dpts[1] = t.val;
		return append_match();
        }
        else{
		iptc_free(h);
                throw std::runtime_error("Couldn't insert rule.");
	}
	return false;
}
bool Iptable::set_udp_field(token& t, struct ipt_udp * udp_){

	clean_udp(udp_);

	if(t.type == "dst_ip"){
                en->nfcache |= NFC_IP_DST_PT;
		return append_match();
        }
        else if(t.type == "src_ip"){
                en->ip.src.s_addr = htonl(t.val);
                en->ip.smsk.s_addr = 0xFFFFFFFF;
                en->nfcache |= NFC_IP_SRC_PT;
		return append_match();
        }
        else if(t.type == "src_port"){
                udp_->spts[0] = udp_->spts[1] = t.val;
		return append_match();
        }
        else if(t.type == "dst_port"){
                udp_->dpts[0] = udp_->dpts[1] = t.val;
		return append_match();
        }
        else{
		iptc_free(h);
                throw std::runtime_error("Couldn't insert rule.");
	}
	return false;
}
bool Iptable::set_icmp_field(token& t, struct ipt_icmp * icmp_){
	
	clean_icmp(icmp_);

	if(t.type == "dst_ip"){
		if(static_cast<int>(icmp_type)>=0){
                	en->nfcache |= NFC_IP_DST_PT;
			return append_match();			
        	}else{
                	rl.en.nfcache |= NFC_IP_DST_PT;
			return cut_match();
		}
	}
        else if(t.type == "src_ip"){
		if(static_cast<int>(icmp_type)>=0){
                	en->ip.src.s_addr = htonl(t.val);
                	en->ip.smsk.s_addr = 0xFFFFFFFF;
                	en->nfcache |= NFC_IP_SRC_PT;
			return append_match();
		}else{
                	rl.en.ip.src.s_addr = htonl(t.val);
                	rl.en.ip.smsk.s_addr = 0xFFFFFFFF;
                	rl.en.nfcache |= NFC_IP_SRC_PT;
			return cut_match();
		}
		
	}
	else if(t.type == "icmp_type"){
		icmp_->type = t.val;
		return append_match();
        }
        else if(t.type == "icmp_code" && static_cast<int>(icmp_type)>=0){
                icmp_->code[0] = icmp_->code[1] = t.val;
		return append_match();			
        }
        else{
		iptc_free(h);
                throw std::runtime_error("Couldn't insert rule.");
	}
	return false;
}
bool Iptable::append_match(){

        memcpy(en->elems, m, m->u.match_size);
	return insert_rule(1);
}
bool Iptable::cut_match(){

	return insert_rule(0);
}

bool Iptable::add_rule(token &t)
{
	if(t.val == 0 && t.type==""){
		return false;
	}
		clean_l3();

		const char * tt = table.c_str();
          	h = iptc_init(tt);


		if(proto == IPPROTO_TCP)
		{
			 struct ipt_tcp * tcp_ = (struct ipt_tcp *) m->data;
                         memset(tcp_, 0, sizeof(*tcp_));	
			 return set_tcp_field(t, tcp_);

		}
		if(proto == IPPROTO_UDP)
                {
			 struct ipt_udp * udp_ = (struct ipt_udp *) m->data;
                         memset(udp_, 0, sizeof(*udp_));
			 return set_udp_field(t, udp_);
                }	
		if(proto == IPPROTO_ICMP)
		{
			struct ipt_icmp * icmp_ = (struct ipt_icmp *) m->data;
			memset(icmp_, 0, sizeof(struct ipt_icmp));
			return set_icmp_field(t, icmp_);
                }	

	return false;
}

