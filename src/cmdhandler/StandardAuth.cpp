#include "StandardAuth.hpp"

#include <fstream>
#include <map>

#include <DateTime.hpp>
#include <ErrCode.hpp>
#include <Log.hpp>
#include <SafePtr.hpp>

extern "C" {
#include <ela_jwt.h>
//} // ela_jwt error

extern "C" {
#define new fix_cpp_keyword_new
#include <crystal.h>
#include <ela_did.h>
#include "../db.h"
#include "../did.h"
#include "../feeds.h"
#undef new
}

namespace trinity {

#define CHECK_DIDSDK(expr, errCode, errDesp) \
    if(!(expr)) { \
        Log::E(Log::Tag::Cmd, errDesp); \
        Log::D(Log::Tag::Cmd, "Did sdk errCode:0x%x, errDesc:%s", \
               DIDError_GetLastErrorCode(), DIDError_GetLastErrorMessage()); \
        CHECK_ERROR(errCode); \
    }

/* =========================================== */
/* === static variables initialize =========== */
/* =========================================== */

/* =========================================== */
/* === static function implement ============= */
/* =========================================== */
std::filesystem::path StandardAuth::GetLocalDocDir()
{
    auto localDocDir = GetDataDir() / LocalDocDirName;
    auto dirExists = std::filesystem::exists(localDocDir);
    if(dirExists == false) {
        dirExists = std::filesystem::create_directories(localDocDir);
    }
    if(dirExists == false) {
        Log::E(Log::Tag::Cmd, "No such directory: %s", localDocDir.c_str());
        localDocDir.clear();
    }

    return localDocDir;
}

int StandardAuth::SaveLocalDIDDocument(DID* did, DIDDocument* doc)
{
    CHECK_ASSERT(did && doc, ErrCode::InvalidArgument);

    auto localDocDir = GetLocalDocDir();
    CHECK_ASSERT(localDocDir.empty() == false, ErrCode::DirectoryNotExistsError);

    auto creater = [](DIDDocument* doc) -> const char* {
        return DIDDocument_ToJson(doc, false);
    };
    auto deleter = [](const char* ptr) -> void {
        if(ptr != nullptr) {
            free(const_cast<char*>(ptr));
        }
    };
    auto docStr = std::shared_ptr<const char>(creater(doc), deleter);
    CHECK_DIDSDK(docStr != nullptr, ErrCode::AuthBadDidDoc, "Failed to format did document to json.");

    auto docFilePath = localDocDir / DID_GetMethodSpecificId(did);
    Log::D(Log::Tag::Cmd, "Save did document to local: %s", docFilePath.c_str());
    std::fstream docStream;
    docStream.open(docFilePath, std::ios::binary | std::ios::out);
    docStream.seekg(0);
    docStream.write(docStr.get(), std::strlen(docStr.get()) + 1);
    docStream.flush();
    docStream.close();

    return 0;
}

DIDDocument* StandardAuth::LoadLocalDIDDocument(DID* did)
{
    if(did == nullptr)
        return nullptr;

    {
        // adapt old process from local_resolver()
        auto oldResolverDoc = local_resolver(did);
        if(oldResolverDoc != nullptr) {
            return oldResolverDoc;
        }
    }

    auto localDocDir = GetLocalDocDir();
    if(localDocDir.empty() == true) {
        Log::E(Log::Tag::Cmd, "Local did document directory is not set.");
        return nullptr;
    };

    auto docFilePath = localDocDir / DID_GetMethodSpecificId(did);
    auto fileExists = std::filesystem::exists(docFilePath);
    if(fileExists == false) {
        return nullptr;
    }
    // Log::D(Log::Tag::Cmd, "Load did document from local: %s", docFilePath.c_str());

    auto docSize = std::filesystem::file_size(docFilePath);
    char *docStr = (char *)alloca(docSize);

    std::fstream docStream;
    docStream.open(docFilePath, std::ios::binary | std::ios::in);
    docStream.seekg(0);
    docStream.read(docStr, docSize);
    docStream.close();

    return DIDDocument_FromJson(docStr);
}

/* =========================================== */
/* === class public function implement  ====== */
/* =========================================== */
StandardAuth::StandardAuth()
{
    using namespace std::placeholders;
    std::map<const char*, AdvancedHandler> advancedHandlerMap {
        {Rpc::Factory::Method::StandardSignIn,  {std::bind(&StandardAuth::onStandardSignIn, this, _1, _2), Accessible::Anyone}},
        {Rpc::Factory::Method::StandardDidAuth, {std::bind(&StandardAuth::onStandardDidAuth, this, _1, _2), Accessible::Anyone}},
    };

    setHandleMap({}, advancedHandlerMap);
}

StandardAuth::~StandardAuth()
{
}

/* =========================================== */
/* === class protected function implement  === */
/* =========================================== */


/* =========================================== */
/* === class private function implement  ===== */
/* =========================================== */
int StandardAuth::onStandardSignIn(std::shared_ptr<Rpc::Request> request,
                                   std::vector<std::shared_ptr<Rpc::Response>> &responseArray)
{
    auto requestPtr = std::dynamic_pointer_cast<Rpc::StandardSignInRequest>(request);
    CHECK_ASSERT(requestPtr != nullptr, ErrCode::InvalidArgument);
    const auto& params = requestPtr->params;
    responseArray.clear();

    auto docCreater = [](const std::string& json) -> DIDDocument* {
        return DIDDocument_FromJson(json.c_str());
    };
    auto docDeleter = [](DIDDocument* ptr) -> void {
        DIDDocument_Destroy(ptr);
    };
    auto didDoc = std::shared_ptr<DIDDocument>(docCreater(params.document), docDeleter);
    CHECK_DIDSDK(didDoc != nullptr, ErrCode::AuthBadDidDoc, "Failed to get did document from json.");

    int valid = DIDDocument_IsValid(didDoc.get());
    CHECK_DIDSDK(valid == 1, ErrCode::AuthDidDocInvlid, "Did document is invalid.");

    auto did = DIDDocument_GetSubject(didDoc.get());
    CHECK_DIDSDK(did, ErrCode::AuthBadDid, "Failed to get did from document.");

    char didStrBuf[ELA_MAX_DID_LEN];
    auto didStr = DID_ToString(did, didStrBuf, sizeof(didStrBuf));
    CHECK_DIDSDK(didStr, ErrCode::AuthBadDidString, "Failed to get did string.");
    Log::D(Log::Tag::Cmd, "Sign in Did: %s", didStr);

    int ret = SaveLocalDIDDocument(did, didDoc.get());
    CHECK_DIDSDK(ret >= 0, ErrCode::AuthSaveDocFailed, "Failed to save did document to local.");

    auto expiration = DateTime::Current() + JWT_EXPIRATION;

    uint8_t nonce[NONCE_BYTES];
    char nonceStr[NONCE_BYTES << 1];
    crypto_random_nonce(nonce);
    crypto_nonce_to_str(nonce, nonceStr, sizeof(nonceStr));

    auto vcPropCreater = [](Credential* vc, const char* key) -> const char* {
        return Credential_GetProperty(vc, key);
    };
    auto vcPropDeleter = [](const char* ptr) -> void {
        if(ptr != nullptr) {
            free(const_cast<char*>(ptr));
        }
    };
    auto serviceName = std::shared_ptr<const char>(vcPropCreater(feeds_vc, "name"), vcPropDeleter);
    auto serviceDesc = std::shared_ptr<const char>(vcPropCreater(feeds_vc, "description"), vcPropDeleter);
    auto serviceElaAddr = std::shared_ptr<const char>(vcPropCreater(feeds_vc, "elaAddress"), vcPropDeleter);

    std::map<const char *, std::string> claimMap = {
        {"nonce", std::string(nonceStr)},
        {"name", std::string(serviceName.get() != nullptr ? serviceName.get() : "")},
        {"description", std::string(serviceDesc.get() != nullptr ? serviceDesc.get() : "")},
        {"elaAddress", std::string(serviceElaAddr.get() != nullptr ? serviceElaAddr.get() : "")},
    };
    std::string challenge;
    ret = makeJwt(expiration, didStr, "DIDAuthChallenge",
                  claimMap,
                  {},
                  challenge);
    CHECK_ERROR(ret);

    authSecretMap[nonceStr] = std::move(AuthSecret{didStr, expiration});

    auto responsePtr = Rpc::Factory::MakeResponse(request->method);
    auto response = std::dynamic_pointer_cast<Rpc::StandardSignInResponse>(responsePtr);
    CHECK_ASSERT(response != nullptr, ErrCode::RpcUnimplementedError);
    response->version = request->version;
    response->id = request->id;
    response->result.jwt_challenge = std::move(challenge);

    responseArray.push_back(response);

    return 0;
}

int StandardAuth::onStandardDidAuth(std::shared_ptr<Rpc::Request> request,
                                    std::vector<std::shared_ptr<Rpc::Response>> &responseArray)
{
    auto requestPtr = std::dynamic_pointer_cast<Rpc::StandardDidAuthRequest>(request);
    CHECK_ASSERT(requestPtr != nullptr, ErrCode::InvalidArgument);
    const auto& params = requestPtr->params;
    responseArray.clear();

    int ret;

    CredentialInfo credentialInfo;
    ret = checkAuthToken(params.user_name, params.jwt_vp, credentialInfo);
    CHECK_ERROR(ret);

    auto userIndex = adaptOldLogin(credentialInfo);
    CHECK_ERROR(userIndex);

    std::string accessToken;
    ret = createAccessToken(credentialInfo, userIndex, accessToken);
    CHECK_ERROR(ret);

    auto responsePtr = Rpc::Factory::MakeResponse(request->method);
    auto response = std::dynamic_pointer_cast<Rpc::StandardDidAuthResponse>(responsePtr);
    CHECK_ASSERT(response != nullptr, ErrCode::RpcUnimplementedError);
    response->version = request->version;
    response->id = request->id;
    response->result.access_token = std::move(accessToken);

    responseArray.push_back(response);

    hdl_stats_changed_notify();

    return 0;
}

std::string StandardAuth::getServiceDid()
{
    char didStrBuf[ELA_MAX_DID_LEN] = {0};

    DID_ToString(DIDURL_GetDid(feeeds_auth_key_url), didStrBuf, sizeof(didStrBuf));

    return std::string(didStrBuf);
}

void StandardAuth::cleanExpiredChallenge()
{
    auto now = DateTime::Current();

    for(auto& it: authSecretMap) {
        if(it.second.expiration < now) {
            authSecretMap.erase(it.first);
        }
    }
}

int StandardAuth::makeJwt(time_t expiration,
                          const std::string& audience,
                          const std::string& subject,
                          const std::map<const char*, std::string>& claimMap,
                          const std::map<const char*, int>& claimIntMap,
                          std::string& jwt)
{
    auto jwtCreater = [](DIDDocument* didDoc) -> JWTBuilder* {
        return DIDDocument_GetJwtBuilder(didDoc);
    };
    auto jwtDeleter = [](JWTBuilder* ptr) -> void {
        JWTBuilder_Destroy(ptr);
    };
    auto jwtBuilder = std::shared_ptr<JWTBuilder>(jwtCreater(feeds_doc), jwtDeleter);
    CHECK_DIDSDK(jwtBuilder != nullptr, ErrCode::AuthBadJwtBuilder, "Failed to get jwt builder from service did");

    int ret = JWTBuilder_SetHeader(jwtBuilder.get(), "typ", "JWT");
    CHECK_DIDSDK(ret, ErrCode::AuthBadJwtHeader, "Failed to set jwt header.");

    ret = JWTBuilder_SetHeader(jwtBuilder.get(), "version", "1.0");
    CHECK_DIDSDK(ret, ErrCode::AuthBadJwtHeader, "Failed to set jwt header.");

    ret = JWTBuilder_SetExpiration(jwtBuilder.get(), expiration);
    CHECK_DIDSDK(ret, ErrCode::AuthBadJwtExpiration, "Failed to set jwt expiration.");

    ret = JWTBuilder_SetAudience(jwtBuilder.get(), audience.c_str());
    CHECK_DIDSDK(ret, ErrCode::AuthBadJwtAudience, "Failed to set jwt audience.");

    ret = JWTBuilder_SetSubject(jwtBuilder.get(), subject.c_str());
    CHECK_DIDSDK(ret, ErrCode::AuthBadJwtSubject, "Failed to set jwt subject.");

    for(const auto& it: claimMap) {
        ret = JWTBuilder_SetClaim(jwtBuilder.get(), it.first, it.second.c_str());
        CHECK_DIDSDK(ret, ErrCode::AuthBadJwtClaim, "Failed to set jwt claim.");
    }
    for(const auto& it: claimIntMap) {
        ret = JWTBuilder_SetClaimWithIntegar(jwtBuilder.get(), it.first, it.second);
        CHECK_DIDSDK(ret, ErrCode::AuthBadJwtClaim, "Failed to set jwt claim integer.");
    }

    int jwtSigned = JWTBuilder_Sign(jwtBuilder.get(), feeeds_auth_key_url, feeds_storepass);
    CHECK_DIDSDK(jwtSigned == 0, ErrCode::AuthJwtSignFailed, "Failed to sign jwt.");

    auto tokenCreater = [](JWTBuilder* jwtBuilder) -> const char* {
        return JWTBuilder_Compact(jwtBuilder);
    };
    auto tokenDeleter = [](const char* ptr) -> void {
        if(ptr != nullptr) {
            free(const_cast<char*>(ptr));
        }
    };
    auto token = std::shared_ptr<const char>(tokenCreater(jwtBuilder.get()), tokenDeleter);
    CHECK_DIDSDK(token != nullptr, ErrCode::AuthJwtCompactFailed, "Failed to compact jwt.");

    jwt = token.get();

    return 0;
}

int StandardAuth::checkAuthToken(const std::string& userName, const std::string& jwtVP,
                                 CredentialInfo& credentialInfo)
{
    CHECK_ASSERT(jwtVP.empty() == false, ErrCode::InvalidArgument);

    /** check jwt token **/
    DIDBackend_SetLocalResolveHandle(StandardAuth::LoadLocalDIDDocument);
    auto jwsCreater = [](const std::string& jwtVP) -> JWT* {
        return DefaultJWSParser_Parse(jwtVP.c_str());
    };
    auto jwsDeleter = [](JWT* ptr) -> void {
        JWT_Destroy(ptr);
    };
    auto jws = std::shared_ptr<JWT>(jwsCreater(jwtVP), jwsDeleter);
    CHECK_DIDSDK(jws != nullptr, ErrCode::AuthBadJwtChallenge, "Failed to parse jws from jwt.");

    auto vpStrCreater = [](JWT *jws) -> const char* {
        return JWT_GetClaimAsJson(jws, "presentation");
    };
    auto vpStrDeleter = [](const char* ptr) -> void {
        if(ptr != nullptr) {
            free(reinterpret_cast<void*>(const_cast<char*>(ptr)));
        }
    };
    auto vpStr = std::shared_ptr<const char>(vpStrCreater(jws.get()), vpStrDeleter);
    CHECK_DIDSDK(vpStr != nullptr, ErrCode::AuthGetJwsClaimFailed, "Failed to get claim from jws.");

    auto vpCreater = [](const char *vpStr) -> Presentation* {
        return Presentation_FromJson(vpStr);
    };
    auto vpDeleter = [](Presentation *ptr) -> void {
        Presentation_Destroy(ptr);
    };
    auto vp = std::shared_ptr<Presentation>(vpCreater(vpStr.get()), vpDeleter);
    CHECK_DIDSDK(vp != nullptr, ErrCode::AuthGetPresentationFailed, "Failed to get presentation from json.");

    /** check vp **/
    int valid = Presentation_IsValid(vp.get());
    CHECK_DIDSDK(valid == 1, ErrCode::AuthInvalidPresentation, "Failed to check presentation.");

    /** check nonce **/
    auto nonce = Presentation_GetNonce(vp.get());
    CHECK_DIDSDK(nonce != nullptr, ErrCode::AuthPresentationEmptyNonce, "Failed to get presentation nonce, return null.");

    auto authSecretIt = authSecretMap.find(nonce); // TODO: change to remove
    CHECK_DIDSDK(authSecretIt != authSecretMap.end(), ErrCode::AuthPresentationBadNonce, "Bad presentation nonce.");
    auto authSecret = authSecretIt->second;

    /** check realm **/
    auto realm = Presentation_GetRealm(vp.get());
    CHECK_DIDSDK(realm != nullptr, ErrCode::AuthPresentationEmptyRealm, "Failed to get presentation realm, return null.");
    CHECK_DIDSDK(getServiceDid() == realm, ErrCode::AuthPresentationBadRealm, "Bad presentation realm.");

    /** check vc **/
    auto count = Presentation_GetCredentialCount(vp.get());
    CHECK_DIDSDK(count >= 1, ErrCode::AuthVerifiableCredentialBadCount, "The credential count is error.");

    Credential **vcArray = (Credential **)alloca(count * sizeof(Credential *));

    int ret = Presentation_GetCredentials(vp.get(), vcArray, count);
    CHECK_DIDSDK(ret >= 1, ErrCode::AuthCredentialNotExists, "The credential isn't exist.");

    auto vc = vcArray[0];
    CHECK_DIDSDK(vc != nullptr, ErrCode::AuthCredentialParseFailed, "The credential string is error, unable to rebuild to a credential object.");

    valid = Credential_IsValid(vc);
    CHECK_DIDSDK(valid == 1, ErrCode::AuthCredentialInvalid, "The credential isn't valid.");

    auto instanceDidUrl = Credential_GetId(vc);
    auto instanceDid = DIDURL_GetDid(instanceDidUrl);
    char *instanceDidBuf = (char *)alloca(ELA_MAX_DID_LEN * sizeof(char));
    auto instanceDidStr = DID_ToString(instanceDid, instanceDidBuf, ELA_MAX_DID_LEN * sizeof(char));
    CHECK_DIDSDK(instanceDidStr != nullptr, ErrCode::AuthCredentialIdNotExists, "The credential id isn't exist.");
    CHECK_ASSERT(authSecret.did == instanceDidStr, ErrCode::AuthCredentialBadInstanceId);

    count = Credential_GetPropertyCount(vc);
    CHECK_DIDSDK(count >= 1, ErrCode::AuthCredentialPropertyNotExists, "The credential property isn't exist.");

    auto vcPropCreater = [](Credential* vc, const char* key) -> const char* {
        return Credential_GetProperty(vc, key);
    };
    auto vcPropDeleter = [](const char* ptr) -> void {
        if(ptr != nullptr) {
            free(const_cast<char*>(ptr));
        }
    };
    auto appDid = std::shared_ptr<const char>(vcPropCreater(vc, "appDid"), vcPropDeleter);
    CHECK_DIDSDK(appDid.get() != nullptr, ErrCode::AuthCredentialPropertyAppIdNotExists, "The credential subject's id isn't exist.");

    bool expired = (authSecret.expiration < DateTime::Current());
    CHECK_ASSERT(expired == false, ErrCode::AuthNonceExpiredError);

    auto issuer = Credential_GetIssuer(vc);
    char issuerDidBuf[ELA_MAX_DID_LEN];
    auto issuerDidStr = DID_ToString(issuer, issuerDidBuf, sizeof(issuerDidBuf));
    credentialInfo.appDid = appDid.get();
    credentialInfo.userDid = issuerDidStr;
    credentialInfo.instanceDid = instanceDidStr;

    credentialInfo.name = (userName.empty() == false ? userName : "NA");
    credentialInfo.email = "NA";

    auto expirationDate = Credential_GetExpirationDate(vc);
    CHECK_DIDSDK(expirationDate > 0, ErrCode::AuthCredentialExpirationError, "Faile to get credential expiration date.");
    credentialInfo.expiration = expirationDate;

    return 0;
}

int StandardAuth::adaptOldLogin(const CredentialInfo& credentialInfo)
{
    UserInfo uinfo;
    memset(&uinfo, 0, sizeof(uinfo));

    uinfo.uid = 0;
    uinfo.did = const_cast<char*>(credentialInfo.userDid.c_str());
    uinfo.name = const_cast<char*>(credentialInfo.name.c_str());
    uinfo.email = const_cast<char*>(credentialInfo.email.c_str());

    if(credentialInfo.userDid == feeds_owner_info.did) {
        int ret = oinfo_upd(&uinfo);
        if(ret < 0) {
            ret = ErrCode::AuthUpdateOwnerError;
        }
        CHECK_ERROR(ret);
    }

    int ret = db_upsert_user(&uinfo, &(uinfo.uid));
    if(ret < 0) {
        ret = ErrCode::AuthUpdateUserError;
    }
    CHECK_ERROR(ret);

    return uinfo.uid;
}

int StandardAuth::createAccessToken(const CredentialInfo& credentialInfo,
                                    int userIndex,
                                    std::string& accessToken)
{
    int ret;
    int64_t expiration = DateTime::Current() + ACCESS_EXPIRATION;
    if(expiration > credentialInfo.expiration) {
        expiration = credentialInfo.expiration;
    }

    ret = makeJwt(expiration, credentialInfo.instanceDid, "AccessToken",
                  {{"appId", credentialInfo.appDid},
                   {"userDid", credentialInfo.userDid},
                   {"appInstanceDid", credentialInfo.instanceDid},
                   {"name", credentialInfo.name},
                   {"email", credentialInfo.email}},
                  // adapt old login
                  {{"uid", userIndex}},
                  accessToken);
    CHECK_ERROR(ret);

    return 0;
}

} // namespace trinity