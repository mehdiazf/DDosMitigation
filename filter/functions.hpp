#ifndef FUNCTIONS_HPP
#define FUNCTIONS_HPP

#include <stdlib.h> // atoi
#include <netinet/in.h>
#include <unistd.h>
#include <net/if.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include <algorithm>
#include <vector>
#include<sys/stat.h>
#include<sys/types.h>
#include<map>
#include<sstream>

#include <boost/format.hpp>
#include <boost/tokenizer.hpp>
#include "exceptions.hpp"

/*
 Divides the input string into elements based on separator and forms
 Result in vector <string>
*/
typedef boost::escaped_list_separator<char> separator_type;
std::vector<std::string> tokenize(const std::string& input,
                                  const boost::char_separator<char>& separator);
std::vector<std::string> tokenize(const std::string& input,
                                  const separator_type& separator);
std::vector<std::string> tokenize(const std::string& input);
std::vector<std::string> space_tokenize(const std::string& input);

template<typename T>
int get_index(const std::vector<T>& vec, const T& value)
{
    auto it = std::find(vec.begin(), vec.end(), value);
    if (it == vec.end())
    {
        throw std::invalid_argument("unsupported value");
    } else
    {
        return std::distance(vec.begin(), it);
    }
}

template <typename T>
std::string to_string(T val)
{
    std::stringstream stream;
    stream << val;
    return stream.str();
}

std::map<std::string, int> filter_tokenize(std::string str);
#endif // end FUNCTIONS_HPP
