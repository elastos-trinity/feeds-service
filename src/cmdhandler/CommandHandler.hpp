#ifndef _FEEDS_COMMAND_HANDLER_HPP_
#define _FEEDS_COMMAND_HANDLER_HPP_

#include <cassert>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <StdFileSystem.hpp>

extern "C" {
#include <obj.h>
#include <rpc.h>
#include <msgq.h>
}

struct ElaCarrier;
struct ElaSession;
struct ElaStreamCallbacks;

namespace trinity {

class ThreadPool;

class CommandHandler {
public:
    /*** type define ***/
    class Listener {
    public:
        enum Accessible {
            Anyone,
            Member,
            Owner,
        };

    protected:
        struct NormalHandler {
            std::function<int(std::shared_ptr<Req>, std::shared_ptr<Resp>&)> callback;
            Accessible accessible;
        };
        struct MultiRespHandler {
            std::function<int(std::shared_ptr<Req>, std::vector<std::shared_ptr<Resp>>&)> callback;
            Accessible accessible;
        };

        static const std::filesystem::path& GetDataDir();

        explicit Listener() = default;
        virtual ~Listener() = default;

        void setHandleMap(const std::map<const char*, NormalHandler>& normalHandlerMap,
                          const std::map<const char*, MultiRespHandler>& multiRespHandlerMap);

        virtual int checkAccessible(Accessible accessible, const std::string& accessToken);
        virtual int onDispose(const std::string& from,
                              std::shared_ptr<Req> req,
                              std::shared_ptr<Resp>& resp);
        virtual int onDispose(const std::string& from,
                              std::shared_ptr<Req> req,
                              std::vector<std::shared_ptr<Resp>>& respArray);
    private:
        static int SetDataDir(const std::filesystem::path& dataDir);
        static std::filesystem::path DataDir;

        int isOwner(const std::string& accessToken);
        int isMember(const std::string& accessToken);
        int getUserInfo(const std::string& accessToken, std::shared_ptr<UserInfo>& userInfo);

        std::map<const char *, NormalHandler> normalHandlerMap;
        std::map<const char *, MultiRespHandler> multiRespHandlerMap;

        friend CommandHandler;
    };

    /*** static function and variable ***/
    static std::shared_ptr<CommandHandler> GetInstance();

    /*** class function and variable ***/
    int config(const std::filesystem::path& dataDir,
               std::weak_ptr<ElaCarrier> carrier);
    void cleanup();

    std::weak_ptr<ElaCarrier> getCarrierHandler();

    int processAsync(const std::string& from, const std::vector<uint8_t>& data);
    int process(const std::string& from, const std::vector<uint8_t>& data);

    int unpackRequest(const std::vector<uint8_t>& data,
                      std::shared_ptr<Req>& req) const;
    int packResponse(const std::shared_ptr<Req>& req,
                     const std::shared_ptr<Resp>& resp,
                     int errCode,
                     std::vector<uint8_t>& data) const;

protected:
    /*** type define ***/

    /*** static function and variable ***/

    /*** class function and variable ***/

private:
    /*** type define ***/

    /*** static function and variable ***/
    static std::shared_ptr<CommandHandler> CmdHandlerInstance;

    /*** class function and variable ***/
    explicit CommandHandler() = default;
    virtual ~CommandHandler() = default;

    std::shared_ptr<ThreadPool> threadPool;
    std::weak_ptr<ElaCarrier> carrierHandler;
    std::vector<std::shared_ptr<Listener>> cmdListener;
};

/***********************************************/
/***** class template function implement *******/
/***********************************************/

/***********************************************/
/***** macro definition ************************/
/***********************************************/

} // namespace trinity

#endif /* _FEEDS_COMMAND_HANDLER_HPP_ */


