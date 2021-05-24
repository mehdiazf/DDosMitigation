//#include <bits/shared_ptr.h>

#include "functions.hpp"

std::vector<std::string> tokenize(const std::string& input, const boost::char_separator<char>& separator)
{
    // Tokenize the intput.
    boost::tokenizer<boost::char_separator<char>> tokens(input, separator);

    // Copy non-empty tokens from the tokenizer into the result.
    std::vector<std::string> result;
    for(const auto& t: tokens)
    {
        if(!t.empty())
        {
            result.push_back(t);
        }
    }
    return result;
}

std::vector<std::string> space_tokenize(const std::string& input)
{
    boost::char_separator<char> sep(" ");

    return tokenize(input, sep);
}

 std::map<std::string, int> filter_tokenize(std::string str){
        
     boost::char_separator<char> sep(",");
     boost::char_separator<char> r_sep(":");
     boost::tokenizer<boost::char_separator<char>> f_type(str, sep);
     
     std::map<std::string, int> result;
     for(const auto& t: f_type){
         
         if(!t.empty()){
              boost::tokenizer<boost::char_separator<char>> tmp(t, r_sep);
              if(tmp.begin() == tmp.end() || (++tmp.begin()) == tmp.end())
                  throw ParserException("bad format in '" + t + "'");
              result[*(tmp.begin())] = std::stoi(*(++tmp.begin()));
             
         }
     }
     return result;                       
    }
 std::vector<std::string> tokenize(const std::string& input, const separator_type& separator)
{
    // Tokenize the intput.
    boost::tokenizer<separator_type> tokens(input, separator);

    // Copy non-empty tokens from the tokenizer into the result.
    std::vector<std::string> result;
    for(const auto& t: tokens)
    {
        if(!t.empty())
        {
            result.push_back(t);
        }
    }
    return result;
}

std::vector<std::string> tokenize(const std::string& input)
{
    separator_type separator("\\",   // The escape characters.
                            " ",     // The separator characters.
                            "\"\'"); // The quote characters.

    return tokenize(input, separator);
}
