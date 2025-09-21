#include <string>
#include <boost/json/object.hpp>

namespace Config
{

std::string RequireString(const boost::json::object& o, const char* key);
int RequireInt(const boost::json::object& o, const char* key);
bool RequireBool(const boost::json::object& o, const char* key);

}