#include "exceptions.hpp"


ParserException::ParserException(const std::string& message) 
    : message_(message) {};
const char* ParserException::what() const throw()
{
    return message_.c_str();
}

RuleException::RuleException(const std::string& message) 
    : message_(message) {};
const char* RuleException::what() const throw()
{
    return message_.c_str();
}

AfpacketException::AfpacketException(const std::string& message) 
    : message_(message) {};
const char* AfpacketException::what() const throw()
{
    return message_.c_str();
}
