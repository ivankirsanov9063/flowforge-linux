#include <string>

#include <boost/json.hpp>

namespace Config
{

std::string RequireString(const boost::json::object& o, const char* key)
{
    if (const boost::json::value* v = o.if_contains(key))
    {
        if (v->is_string())
            return boost::json::value_to<std::string>(*v);
    }
    throw std::runtime_error(std::string("missing or invalid string field '") + key + "'");
};

int RequireInt(const boost::json::object& o, const char* key)
{
    if (const boost::json::value* v = o.if_contains(key))
    {
        if (v->is_int64())  return static_cast<int>(v->as_int64());
        if (v->is_uint64()) return static_cast<int>(v->as_uint64());
        if (v->is_string())
        {
            const auto s = boost::json::value_to<std::string>(*v);
            try { return std::stoi(s); } catch (...) {}
        }
    }
    throw std::runtime_error(std::string("missing or invalid integer field '") + key + "'");
};

bool RequireBool(const boost::json::object& o, const char* key)
{
    if (const boost::json::value* v = o.if_contains(key))
    {
        if (v->is_bool()) return v->as_bool();
        if (v->is_string())
        {
            std::string s = boost::json::value_to<std::string>(*v);
            std::transform(s.begin(), s.end(), s.begin(),
                           [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            if (s == "1" || s == "true"  || s == "yes" || s == "on")  return true;
            if (s == "0" || s == "false" || s == "no"  || s == "off") return false;
        }
    }
    throw std::runtime_error(std::string("missing or invalid boolean field '") + key + "'");
};


}