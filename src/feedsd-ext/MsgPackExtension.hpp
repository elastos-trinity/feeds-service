#ifndef _FEEDS_MSGPACK_EXTENSION_HPP_
#define _FEEDS_MSGPACK_EXTENSION_HPP_

#include <sstream>
#include <string>

#define MSGPACK_USE_DEFINE_MAP
#include <msgpack.hpp>

#define DECLARE_DEFAULT_STRUCT(name)  \
    explicit name() = default; \
    virtual ~name() = default \

#define MSGPACK_DEFINE_STRUCT(name, ...)  \
    virtual void pack(msgpack::sbuffer& buf) { \
        msgpack::pack(buf, *this); \
    } \
    virtual void unpack(const msgpack::object& obj) { \
        obj.convert(*this); \
    } \
    virtual std::string str() { \
        std::stringstream sstream; \
        msgpack::zone z; \
        auto obj = msgpack::object(*this, z); \
        sstream << obj; \
        return sstream.str(); \
    } \
    DECLARE_DEFAULT_STRUCT(name); \
    MSGPACK_DEFINE(__VA_ARGS__)

#define MSGPACK_DEFINE_WITHTOKEN(name, token, ...)  \
    virtual const std::string& accessToken() { return token; } \
    MSGPACK_DEFINE_STRUCT(name, __VA_ARGS__)

#define MSGPACK_REQUEST_ARGS \
    version, method, id

#define MSGPACK_REQUEST_TOKEN_ARGS \
    access_token

#define MSGPACK_RESPONSE_ARGS \
    version, id


#endif /* _FEEDS_MSGPACK_EXTENSION_HPP_ */


