#ifndef CommandParser_HPP
#define CommandParser_HPP

#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <bitset>
#include <string>
#include <cstdlib>

#include <boost/program_options.hpp>
#include <boost/asio/ip/address.hpp>

#include "exceptions.hpp"
//#include "action.hpp"
#include "functions.hpp"


namespace parser
{
    // Abbreviations for bytes / sec
    const std::vector<std::string> pref_b = { "b/s", "Kb/s", "Mb/s",
                                              "Gb/s", "Tb/s", "Pb/s" };
    // abbreviations for packet / sec
    const std::vector<std::string> pref_p = { "p/s", "Kp/s", "Mp/s",
                                              "Gp/s", "Tp/s", "Pp/s" };
    // Abbreviations for the number of bytes
    const std::vector<std::string> size_b = { "b", "Kb", "Mb",
                                              "Gb", "Tb", "Pb" };
    // Abbreviations for the number of packages 
    const std::vector<std::string> size_p = { "p", "Kp", "Mp",
                                              "Gp", "Tp", "Pp" };
    // Possible characters to indicate the type of comparison
    const std::vector<char> comp_t = { '=', '>', '<' };

    /*
    Class for parsing the string representation of rules and parsing commands
    */
    class CommandParser
    {
    public:
        explicit CommandParser(
            const  boost::program_options::options_description& opt);
        /*
         Adding options to the current options_
         @param opt: options to add
        */
        void add_opt(const boost::program_options::options_description& opt);
        /*
         Parsing a rule, checking parameters for erroneous
         @param tokenize_input: the rule string split into a vector by spaces
        */
        boost::program_options::variables_map parse(
            const std::vector<std::string>& tokenize_input);
        /*
         Displaying help for commands from the current options_
        */
        void help() const;
        /*
         Reverse operation - gluing vector <string> into one line
         @param v: the vector of strings to be concatenated
        */
        static std::string join(const std::vector<std::string>& v);
    private:
        boost::program_options::options_description options_;
    };

    // FUNCTIONS parser::
    /*
     Parsing a string with an ip address (1.1.1.1) or ip network (1.1.1.1/24) into
     NumRange representation: start_ip and end_ip. Function converts ip
     Address from CIDR submission to ulong, calculates first and last
     Address by subnet mask and forms pair <uint32_t, uint32_t>
     If the function is passed a string from ip addresses without a subnet, then
     Pair.first = pair.second.
    */
    std::pair<uint32_t, uint32_t> range_from_ip_string(const std::string& ipstr);
    /*
     Parsing a range of values ​​from a string: <num> - <num> or <num>.
     If one number is passed, without '-', then return pair.first = pair.second
    */
    std::pair<uint16_t, uint16_t> range_from_port_string(const std::string& portstr);
    /*
     Converting a number into a short record indicating the type (for example: 10Mb).
     @param size: number to convert
     @param its_byte: type of number, bytes or packets (Mp or Mb)
    */
    std::string to_short_size(unsigned long int size, bool its_byte = true);
    /*
    Converts short notation of number with type to number uint64_t.
     @param size: the string to be converted
     @param its_byte: type of number, bytes or packets (Mp or Mb)
    */
    uint64_t from_short_size(const std::string& size, bool its_byte = true);
    /*
     Converting the string rule action to an instance of the action :: Action class
     The function checks for compliance with the format <type>: <param>
    */
    //action::Action action_from_string(const std::string& value);
    /*
     Converting the comparison rule (format:> num, <num, = num) to
     Pair <T, type_comp> where type_comp is the number corresponding to the type of operation
     Comparisons Ж 0 is =,> this is 1, <is 2 (see const comp_t).
    */
    template<typename T>
    std::pair<T, unsigned short int> numcomp_from_string(const std::string& value)
    {
        if(value.length() < 2)
        {
            throw ParserException("parametr '" + value + "' is too short, must be '>num', '=num' or '<num'");
        }
        size_t bad = 0;
        unsigned long int num;
        try
        {
            //num = std::atoi(value.substr(1).c_str());
            num = std::stoul(value.substr(1), &bad);
        }
        catch(const std::invalid_argument& e)
        {
            throw ParserException("bad number in '" + value.substr(1) + "'");
        }
        if((bad+1) != value.length()) // if unparsed symbols in string
        {
            throw ParserException("unparsed symbols in '" + value + "', must be '>num', '=num' or '<num'");
        }
        return std::make_pair/*<T, unsigned short int>*/((T)num, get_index<char>(comp_t, value.at(0)));
    }
    /*
     Converting a string of the form: f1: 0, f2: 1, f3: 1, fn: [0,1] into pair <bits, mask>,
     Where bits is the bitset of the state of the flags, i.e. 0 and 1 from example fn: [0,1]
     A mask is a bitset mask indicating which bits to check. Every flag
     Is checked for correctness according to the accept_flags list, from which it is taken
     Position.

     Example:
     vector<char> f_accept = { 'U', 'A', 'P', 'R', 'S', 'F' };
     pair<bitset<6>, bitset<6>> ex;
     ex = bitset_from_string<bitset<6>>('U:0,S:1,F:0');
     cout << 'bits: ' << ex.first << endl;
     cout << 'mask: ' << ex.second << endl;

     Result:
     bits: 000010
     mask: 100011
    */
    template<typename T>
    std::pair<T, T> bitset_from_string(const std::string& value,
        const std::vector<char>& accept_flags)
    {
        T bits;
        T mask;
        if(accept_flags.size() != bits.size())
            throw std::invalid_argument("bad parametr accept flags");
        separator_type separator("\\",    // The escape characters.
                                 ",",    // The separator characters.
                                 "\"\'"); // The quote characters.
        std::vector<std::string> tok_v = tokenize(value, separator);
        if(tok_v.empty())
            throw ParserException("empty option '" + value + "'");
        int indx;
        for(auto& f: tok_v)
        {
            if(f.length() != 3 || f.at(1) != ':'
                || (f.at(2) != '0' && f.at(2) != '1'))
            {
                throw ParserException("unparsed flag '" + f + "', must be: '<flag>:<enable>', where <enable> - 0 or 1.");
            }
            indx = get_index<char>(accept_flags, f.at(0)); // check if flag accept
            mask[indx] = true; // enable bit in mask
            bits[indx] = f.at(2)=='1' ? true : false; // add checked bit
        }
        return std::make_pair(bits, mask);
    }
        
}

#endif // end CommandParser_HPP
