//********************************************************
/**
 * @file  WebServer.cc
 *
 * @brief HTTP multithreaded Server
 *        rfc2616 compliant (HTTP1.1)
 *        rfc5280 X509 authentification
 *
 * @author T.Descombes (thierry.descombes@gmail.com)
 *
 * @version 1
 * @date 19/02/15
 */
//********************************************************

#include <sys/stat.h>

#include <cctype>
#include <csignal>
#include <pthread.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <locale>
#include <sstream>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <libnavajo/HttpRequest.hh>

#include "libnavajo/GrDebug.hpp"
#include "libnavajo/WebServer.hh"
#include "libnavajo/WebSocket.hh"
#include "libnavajo/htonll.h"
#include "libnavajo/nvjGzip.h"
#include "libnavajo/nvjSocket.h"

#include "MPFDParser/Parser.h"

#define DEFAULT_HTTP_SERVER_SOCKET_TIMEOUT 3
#define DEFAULT_HTTP_PORT                  8080
#define LOGHIST_EXPIRATION_DELAY           600
#define BUFSIZE                            32768
#define KEEPALIVE_MAX_NB_QUERY             25

const char                            WebServer::authStr[]       = "Authorization: Basic ";
const char                            WebServer::authBearerStr[] = "Authorization: Bearer ";
const int                             WebServer::verify_depth    = 512;
char                                 *WebServer::certpass        = nullptr;
std::string                           WebServer::webServerName;
pthread_mutex_t                       IpAddress::resolvIP_mutex = PTHREAD_MUTEX_INITIALIZER;
HttpSession::HttpSessionsContainerMap HttpSession::sessions;
pthread_mutex_t                       HttpSession::sessions_mutex     = PTHREAD_MUTEX_INITIALIZER;
const std::string                     WebServer::base64_chars         = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                                                        "abcdefghijklmnopqrstuvwxyz"
                                                                        "0123456789+/";
const std::string                     WebServer::webSocketMagicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

std::map<unsigned, const char *> HttpResponse::mHttpReturnCodes;
time_t                           HttpSession::lastExpirationSearchTime = 0;
time_t                           HttpSession::sessionLifeTime          = 20 * 60;

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/*********************************************************************/

// clang-format off
WebServer::WebServer() :
  sslCtx(nullptr),
  s_server_session_id_context(1),
  tokDecodeCallback(nullptr),
  authBearTokDecExpirationCb(nullptr),
  authBearTokDecScopesCb(nullptr),
  authBearerEnabled(false),
  httpdAuth(false),
  exiting(false),
  exitedThread(0),
  nbServerSock(0),
  disableIpV4(false),
  disableIpV6(false),
  socketTimeoutInSecond(DEFAULT_HTTP_SERVER_SOCKET_TIMEOUT),
  tcpPort(DEFAULT_HTTP_PORT),
  threadsPoolSize(64),
  multipartMaxCollectedDataLength(20 * 1024),
  mIsSSLEnabled(false),
  mIsAuthPeerSSL(false)
{
  GR_JUMP_TRACE;

  webServerName                 = std::string( "Server: libNavajo/" ) + std::string( LIBNAVAJO_SOFTWARE_VERSION );
  multipartTempDirForFileUpload = "/tmp";

  pthread_mutex_init( &clientsQueue_mutex, nullptr );
  pthread_cond_init( &clientsQueue_cond, nullptr );

  pthread_mutex_init( &peerDnHistory_mutex, nullptr );
  pthread_mutex_init( &usersAuthHistory_mutex, nullptr );
  pthread_mutex_init( &tokensAuthHistory_mutex, nullptr );
}
// clang-format on

/*********************************************************************/

void WebServer::updatePeerIpHistory(IpAddress &ip) {
  GR_JUMP_TRACE;
  time_t t = time(nullptr);
  auto   i = peerIpHistory.find(ip);

  bool dispPeer = false;
  if (i != peerIpHistory.end()) {
    dispPeer  = t - i->second > LOGHIST_EXPIRATION_DELAY;
    i->second = t;
  } else {
    peerIpHistory[ip] = t;
    dispPeer          = true;
  }

  if (dispPeer) {
    spdlog::debug(std::string("WebServer: Connection from IP: ") + ip.str());
  }
}

/*********************************************************************/

void WebServer::updatePeerDnHistory(std::string dn) {
  GR_JUMP_TRACE;

  pthread_mutex_lock(&peerDnHistory_mutex);
  time_t t = time(nullptr);
  auto   i = peerDnHistory.find(dn);

  bool dispPeer = false;
  if (i != peerDnHistory.end()) {
    dispPeer  = t - i->second > LOGHIST_EXPIRATION_DELAY;
    i->second = t;
  } else {
    peerDnHistory[dn] = t;
    dispPeer          = true;
  }

  if (dispPeer) {
    spdlog::debug("WebServer: Authorized DN: " + dn);
  }

  pthread_mutex_unlock(&peerDnHistory_mutex);
}

/*********************************************************************/
/**
 * Http login authentification
 * @param name: the login/password string in base64 format
 * @param name: set to the decoded login name
 * @return true if user is allowed
 */
bool WebServer::isUserAllowed(const std::string &pwdb64, std::string &login) {
  GR_JUMP_TRACE;

  pthread_mutex_lock(&usersAuthHistory_mutex);
  time_t t = time(nullptr);

  bool isNewUser = true;
  auto i         = usersAuthHistory.find(pwdb64);

  if (i != usersAuthHistory.end()) {
    isNewUser = t - i->second > LOGHIST_EXPIRATION_DELAY;
    i->second = t;
  }

  if (!isNewUser) {
    pthread_mutex_unlock(&usersAuthHistory_mutex);
    return true;
  }

  // It's a new user !
  bool        authOK      = false;
  std::string loginPwd    = base64_decode(pwdb64.c_str());
  size_t      loginPwdSep = loginPwd.find(':');
  if (loginPwdSep == std::string::npos) {
    pthread_mutex_unlock(&usersAuthHistory_mutex);
    return false;
  }

  login           = loginPwd.substr(0, loginPwdSep);
  std::string pwd = loginPwd.substr(loginPwdSep + 1);

  std::vector<std::string> httpAuthLoginPwd = authLoginPwdList;
  if (httpAuthLoginPwd.size()) {
    std::string logPass = login + ':' + pwd;
    for (auto &it : httpAuthLoginPwd) {
      if (logPass == it) {
        authOK = true;
      }
    }
  }

  if (authOK) {
    spdlog::info("WebServer: Authentification passed for user '{}'", login);
    if (i == usersAuthHistory.end()) {
      usersAuthHistory[pwdb64] = t;
    }
  } else {
    spdlog::debug("WebServer: Authentification failed for user '{}'", login);
  }

  pthread_mutex_unlock(&usersAuthHistory_mutex);
  return authOK;
}

/**
 * Http Bearer token authentication
 * @param tokb64: the token string in base64 format
 * @param resourceUrl: the token string in base64 format
 * @param respHeader: headers to add in HTTP response in case of failed
 * authentication, on tail of WWW-Authenticate
 * attribute
 * @return true if token is allowed
 */
bool WebServer::isTokenAllowed(const std::string &tokb64, const std::string &resourceUrl, std::string &respHeader) {
  GR_JUMP_TRACE;
  std::string    logAuth    = "WebServer: Authentication passed for token '" + tokb64 + "'";
  NvjLogSeverity logAuthLvl = NVJ_DEBUG;
  time_t         t          = time(nullptr);
  struct tm     *timeinfo;
  bool           isTokenExpired = true;
  bool           authOK         = false;
  time_t         expiration     = 0;

  timeinfo = localtime(&t);
  t        = mktime(timeinfo);

  pthread_mutex_lock(&tokensAuthHistory_mutex);
  auto i = tokensAuthHistory.find(tokb64);

  if (i != tokensAuthHistory.end()) {
    spdlog::debug("WebServer: token already authenticated");

    /* get current timeinfo and compare to the one previously stored */
    isTokenExpired = t > i->second;

    if (isTokenExpired) {
      /* Remove token from the map to avoid infinite grow of it */
      tokensAuthHistory.erase(tokb64);
      spdlog::debug("WebServer: removing outdated token from cache '" + tokb64 + "'");
    }

    pthread_mutex_unlock(&tokensAuthHistory_mutex);
    return !isTokenExpired;
  }

  // It's a new token !

  std::string tokDecoded;

  // Use callback configured to decode token
  if (tokDecodeCallback(tokb64, tokDecodeSecret, tokDecoded)) {
    logAuth    = "WebServer: Authentication failed for token '" + tokb64 + "'";
    respHeader = "realm=\"" + authBearerRealm;
    respHeader += R"(",error="invalid_token", error_description="invalid signature")";
    goto end;
  }

  // retrieve expiration date
  expiration = authBearTokDecExpirationCb(tokDecoded);

  if (!expiration) {
    logAuth = "WebServer: Authentication failed, expiration date not found for "
              "token '" +
              tokb64 + "'";
    respHeader = "realm=\"" + authBearerRealm;
    respHeader += "\",error=\"invalid_token\", error_description=\"no "
                  "expiration in token\"";
    goto end;
  }

  if (expiration < t) {
    logAuth    = "WebServer: Authentication failed, validity expired for token '" + tokb64 + "'";
    respHeader = "realm=\"" + authBearerRealm;
    respHeader += R"(",error="invalid_token", error_description="token expired")";
    goto end;
  }

  // check for extra attribute if any callback was set to that purpose
  if (authBearTokDecScopesCb) {
    std::string errDescr;

    if (authBearTokDecScopesCb(tokDecoded, resourceUrl, errDescr)) {
      logAuth    = "WebServer: Authentication failed, invalid scope for token '" + tokb64 + "'";
      respHeader = "realm=\"" + authBearerRealm;
      respHeader += R"(",error="insufficient_scope",error_description=")";
      respHeader += errDescr + "\"";
      goto end;
    }
  }

  // All checks passed successfully, store the token to speed up processing of
  // next request
  // proposing same token
  authOK                    = true;
  logAuthLvl                = NVJ_INFO;
  tokensAuthHistory[tokb64] = expiration;

end:
  pthread_mutex_unlock(&tokensAuthHistory_mutex);
  spdlog::info(logAuth);

  return authOK;
}

/***********************************************************************
 * recvLine:  Receive an ascii line from a socket
 * @param c - the socket connected to the client
 * \return always NULL
 ***********************************************************************/

size_t WebServer::recvLine(int client, char *bufLine, size_t nsize) {
  GR_JUMP_TRACE;

  size_t bufLineLen = 0;
  char   c;
  int    n;
  do {
    n = recv(client, &c, 1, 0);

    if (n > 0) {
      bufLine[bufLineLen++] = c;
    }
  } while ((bufLineLen + 1 < nsize) && (c != '\n') && (n > 0));
  bufLine[bufLineLen] = '\0';

  return bufLineLen;
}

/**********************************************************************/
/**
 * trim from start, thanks to https://stackoverflow.com/a/217605
 */
static inline std::string &ltrim(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
  return s;
}

/**********************************************************************/
/**
 * trim from end, thanks to https://stackoverflow.com/a/217605
 */
static inline std::string &rtrim(std::string &s) {
  s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
  return s;
}

/**********************************************************************/
/**
 * trim from both ends, thanks to https://stackoverflow.com/a/217605
 */
static inline std::string &trim(std::string &s) { return ltrim(rtrim(s)); }

/**********************************************************************/
/**
 * fill extra http headers Map
 * @param c: raw string containing a header line made of "Header: Value"
 */
static void addExtraHeader(const char *l, HttpRequestHeadersMap &m) {
  std::stringstream ss(l);
  std::string       header;
  std::string       val;
  if (std::getline(ss, header, ':') && std::getline(ss, val, ':')) {
    m[header] = trim(val);
  }
};

/***********************************************************************
 * accept_request:  Process a request
 * @param c - the socket connected to the client
 * \return true if the socket must to close
 ***********************************************************************/

bool WebServer::accept_request(ClientSockData *clientSockData, bool /*authSSL*/) {
  GR_JUMP_TRACE;
  char              bufLine[BUFSIZE];
  HttpRequestMethod requestMethod;
  size_t            requestContentLength = 0;
  bool              urlencodedForm       = false;

  std::vector<uint8_t> payload;
  char                 mimeType[64] = "\0";

  char         *urlBuffer              = nullptr;
  char         *multipartContent       = nullptr;
  size_t        nbFileKeepAlive        = KEEPALIVE_MAX_NB_QUERY;
  MPFD::Parser *multipartContentParser = nullptr;
  char         *requestParams          = nullptr;
  char         *requestCookies         = nullptr;
  char         *requestOrigin          = nullptr;
  HttpRequestHeadersMap requestExtraHeaders;
  char         *webSocketClientKey     = nullptr;
  bool          websocket              = false;
  int           webSocketVersion       = -1;
  std::string   username;
  int           bufLineLen = 0;

  unsigned i = 0, j = 0;

  bool        authOK      = authLoginPwdList.size() == 0;
  char        httpVers[4] = "";
  bool        keepAlive   = false;
  bool        closing     = false;
  bool        isQueryStr  = false;
  std::string authRespHeader;

  if (authBearerEnabled) {
    authOK         = false;
    authRespHeader = "realm=\"Restricted area: please provide valid token\"";
  }

  do {
    GR_JUMP_TRACE;
    // Initialisation /////////
    requestMethod        = UNKNOWN_METHOD;
    requestContentLength = 0;
    urlencodedForm       = false;
    username             = "";
    keepAlive            = false;
    closing              = false;
    isQueryStr           = false;

    if (urlBuffer != nullptr) {
      GR_JUMP_TRACE;
      free(urlBuffer);
      urlBuffer = nullptr;
    };
    if (requestParams != nullptr) {
      GR_JUMP_TRACE;
      free(requestParams);
      requestParams = nullptr;
    };
    if (requestCookies != nullptr) {
      GR_JUMP_TRACE;
      free(requestCookies);
      requestCookies = nullptr;
    };
    if (requestOrigin != nullptr) {
      GR_JUMP_TRACE;
      free(requestOrigin);
      requestOrigin = nullptr;
    };
    if (webSocketClientKey != nullptr) {
      GR_JUMP_TRACE;
      free(webSocketClientKey);
      webSocketClientKey = nullptr;
    };
    if (multipartContent != nullptr) {
      GR_JUMP_TRACE;
      free(multipartContent);
      multipartContent = nullptr;
    };
    if (multipartContentParser != nullptr) {
      GR_JUMP_TRACE;
      delete multipartContentParser;
      multipartContentParser = nullptr;
    };

    websocket        = false;
    webSocketVersion = -1;

    //////////////////////////

    while (true) {
      GR_JUMP_TRACE;
      bufLineLen = 0;
      *bufLine   = '\0';

      if (mIsSSLEnabled) {
        GR_JUMP_TRACE;
        int r = BIO_gets(clientSockData->bio, bufLine, BUFSIZE - 1);

        switch (SSL_get_error(clientSockData->ssl, r)) {
        case SSL_ERROR_NONE:
          GR_JUMP_TRACE;
          if ((r == 0) || (r == -1)) {
            continue;
          }
          bufLineLen = r;
          break;
        case SSL_ERROR_ZERO_RETURN:
          GR_JUMP_TRACE;
          spdlog::debug("WebServer::accept_request - BIO_gets() "
                        "failed with SSL_ERROR_ZERO_RETURN - 1");
          goto FREE_RETURN_TRUE;
        }
      } else {
        GR_JUMP_TRACE;
        bufLineLen = recvLine(clientSockData->socketId, bufLine, BUFSIZE - 1);
      }

      if (bufLineLen == 0 || exiting) {
        GR_JUMP_TRACE;
        goto FREE_RETURN_TRUE;
      }

      if (bufLineLen <= 2) {
        GR_JUMP_TRACE;
        // only CRLF found (empty line) -> decoding is finished !
        if ((*bufLine == '\n') || (*bufLine == '\r' && *(bufLine + 1) == '\n')) {
          GR_JUMP_TRACE;
          break;
        }
      } else {
        GR_JUMP_TRACE;
        if (bufLineLen == BUFSIZE - 1) {
          GR_JUMP_TRACE;
          *(bufLine + bufLineLen) = '\0';
        } else {
          GR_JUMP_TRACE;
          *(bufLine + bufLineLen - 2) = '\0';
        }
        j = 0;
        while (j < (unsigned)bufLineLen && isspace((int)(bufLine[j]))) {
          GR_JUMP_TRACE;
          j++;
        }

        // decode login/passwd
        if (strncmp(bufLine + j, authStr, sizeof authStr - 1) == 0) {
          GR_JUMP_TRACE;
          j += sizeof authStr - 1;

          std::string pwdb64 = "";
          while (j < (unsigned)bufLineLen && *(bufLine + j) != 0x0d && *(bufLine + j) != 0x0a) {
            GR_JUMP_TRACE;
            pwdb64 += *(bufLine + j++);
          };
          if (!authOK) {
            GR_JUMP_TRACE;
            authOK = isUserAllowed(pwdb64, username);
          }
          continue;
        }

        // decode HTTP headers
        if (strncasecmp(bufLine + j, "Connection: ", 12) == 0) {
          GR_JUMP_TRACE;
          j += 12;
          if (strstr(bufLine + j, "pgrade") != nullptr) {
            GR_JUMP_TRACE;
            websocket = true;
          } else {
            if (strstr(bufLine + j, "lose") != nullptr) {
              GR_JUMP_TRACE;
              closing = false;
            } else if ((strstr(bufLine + j, "eep-") != nullptr) && (strstr(bufLine + j + 4, "live") != nullptr)) {
              GR_JUMP_TRACE;
              keepAlive = true;
            }
          }
          continue;
        }

        if (strncasecmp(bufLine + j, "Accept-Encoding: ", 17) == 0) {
          GR_JUMP_TRACE;
          j += 17;
          if (strstr(bufLine + j, "gzip") != nullptr) {
            GR_JUMP_TRACE;
            clientSockData->compression = GZIP;
          }
          continue;
        }

        if (strncasecmp(bufLine + j, "Content-Type: ", 14) == 0) {
          GR_JUMP_TRACE;
          j += 14;
          char  *start = bufLine + j, *end = nullptr;
          size_t length = 0;
          if ((end = index(start, ';')) != nullptr) {
            GR_JUMP_TRACE;
            length = end - start;
          } else {
            GR_JUMP_TRACE;
            length = strlen(start);
          }
          if (length >= 63) {
            GR_JUMP_TRACE;
            length = 63;
          }
          strncpy(mimeType, start, length);
          mimeType[length] = '\0';

          if (strncasecmp(mimeType, "application/x-www-form-urlencoded", 33) == 0) {
            GR_JUMP_TRACE;
            urlencodedForm = true;
          } else if (strncasecmp(mimeType, "multipart/form-data", 19) == 0) {
            GR_JUMP_TRACE;
            multipartContent = (char *)malloc((strlen(bufLine + j) + 1) * sizeof(char));
            strcpy(multipartContent, bufLine + j);
          }
          continue;
        }

        if (strncasecmp(bufLine + j, "Content-Length: ", 16) == 0) {
          GR_JUMP_TRACE;
          j += 16;
          requestContentLength = atoi(bufLine + j);
          continue;
        }

        if (strncasecmp(bufLine + j, "Cookie: ", 8) == 0) {
          GR_JUMP_TRACE;
          j += 8;
          requestCookies = (char *)malloc((strlen(bufLine + j) + 1) * sizeof(char));
          strcpy(requestCookies, bufLine + j);
          continue;
        }

        if (strncasecmp(bufLine + j, "Origin: ", 8) == 0) {
          GR_JUMP_TRACE;
          j += 8;
          requestOrigin = (char *)malloc((strlen(bufLine + j) + 1) * sizeof(char));
          strcpy(requestOrigin, bufLine + j);
          continue;
        }

        if (strncasecmp(bufLine + j, "Sec-WebSocket-Key: ", 19) == 0) {
          GR_JUMP_TRACE;
          j += 19;
          webSocketClientKey = (char *)malloc((strlen(bufLine + j) + 1) * sizeof(char));
          strcpy(webSocketClientKey, bufLine + j);
          continue;
        }

        if (strncasecmp(bufLine + j, "Sec-WebSocket-Extensions: ", 26) == 0) {
          GR_JUMP_TRACE;
          j += 26;
          if (strstr(bufLine + j, "permessage-deflate") != nullptr) {
            clientSockData->compression = ZLIB;
          }
          continue;
        }

        if (strncasecmp(bufLine + j, "Sec-WebSocket-Version: ", 23) == 0) {
          GR_JUMP_TRACE;
          j += 23;
          webSocketVersion = atoi(bufLine + j);
          continue;
        }

        addExtraHeader(bufLine + j, requestExtraHeaders);
        isQueryStr = false;
        if (strncmp(bufLine + j, "GET", 3) == 0) {
          GR_JUMP_TRACE;
          requestMethod = GET_METHOD;
          isQueryStr    = true;
          j += 4;
        } else if (strncmp(bufLine + j, "POST", 4) == 0) {
          GR_JUMP_TRACE;
          requestMethod = POST_METHOD;
          isQueryStr    = true;
          j += 5;
        } else if (strncmp(bufLine + j, "PUT", 3) == 0) {
          GR_JUMP_TRACE;
          requestMethod = PUT_METHOD;
          isQueryStr    = true;
          j += 4;
        } else if (strncmp(bufLine + j, "DELETE", 6) == 0) {
          GR_JUMP_TRACE;
          requestMethod = DELETE_METHOD;
          isQueryStr    = true;
          j += 7;
        } else if (strncmp(bufLine + j, "UPDATE", 6) == 0) {
          GR_JUMP_TRACE;
          requestMethod = UPDATE_METHOD;
          isQueryStr    = true;
          j += 7;
        } else if (strncmp(bufLine + j, "PATCH", 5) == 0) {
          GR_JUMP_TRACE;
          requestMethod = PATCH_METHOD;
          isQueryStr    = true;
          j += 6;
        } else if (strncmp(bufLine + j, "OPTIONS", 7) == 0) {
          GR_JUMP_TRACE;
          requestMethod = OPTIONS_METHOD;
          isQueryStr    = true;
          j += 7;
        }

        if (isQueryStr) {
          GR_JUMP_TRACE;
          while (j < (unsigned)bufLineLen && isspace((int)(bufLine[j]))) {
            GR_JUMP_TRACE;
            j++;
          }

          // Decode URL
          urlBuffer = (char *)malloc((strlen(bufLine + j) + 1) * sizeof(char));
          i         = 0;
          while (!isspace((int)(bufLine[j])) && (i < BUFSIZE - 1) && (j < (unsigned)bufLineLen) && bufLine[j] != '?') {
            GR_JUMP_TRACE;
            if (!i && (bufLine[j] == '/')) { // remove first '/'
              j++;
            } else {
              urlBuffer[i++] = bufLine[j++];
            }
          }
          urlBuffer[i] = '\0';

          // Decode GET Parameters
          if (!urlencodedForm && (bufLine[j] == '?')) {
            GR_JUMP_TRACE;
            i = 0;
            j++;
            requestParams = (char *)malloc(BUFSIZE * sizeof(char));
            while (!isspace((int)(bufLine[j])) && (i < BUFSIZE - 1) && (j < (unsigned)bufLineLen)) {
              requestParams[i++] = bufLine[j++];
            }
            requestParams[i] = '\0';
          }

          while (j < (unsigned)bufLineLen && isspace((int)(bufLine[j]))) {
            GR_JUMP_TRACE;
            j++;
          }
          if (strncmp(bufLine + j, "HTTP/", 5) == 0) {
            GR_JUMP_TRACE;
            strncpy(httpVers, bufLine + j + 5, 3);
            *(httpVers + 3) = '\0';
            j += 8;
            // HTTP/1.1 default behavior is to support keepAlive
            keepAlive = strncmp(httpVers, "1.1", 3) >= 0;
          }
        }

        //  authorization through bearer token, RFC 6750
        if (strncmp(bufLine + j, authBearerStr, sizeof authBearerStr - 1) == 0) {
          GR_JUMP_TRACE;
          j += sizeof authStr;

          std::string tokb64 = "";
          while (j < (unsigned)bufLineLen && *(bufLine + j) != 0x0d && *(bufLine + j) != 0x0a) {
            GR_JUMP_TRACE;
            tokb64 += *(bufLine + j++);
          }
          if (authBearerEnabled) {
            GR_JUMP_TRACE;
            authOK = isTokenAllowed(tokb64, urlBuffer, authRespHeader);
          }
          continue;
        }
      }
    }

    if (!authOK) {
      GR_JUMP_TRACE;
      const char *abh = authRespHeader.empty() ? nullptr : authRespHeader.c_str();
      std::string msg = getHttpHeader("401 Authorization Required", 0, false, abh);
      httpSend(clientSockData, (const void *)msg.c_str(), msg.length());
      goto FREE_RETURN_TRUE;
    }

    if (requestMethod == UNKNOWN_METHOD) {
      GR_JUMP_TRACE;
      std::string msg = getNotImplementedErrorMsg();
      httpSend(clientSockData, (const void *)msg.c_str(), msg.length());
      goto FREE_RETURN_TRUE;
    }

    // update URL to load the default index.html page
    if ((*urlBuffer == '\0' || *(urlBuffer + strlen(urlBuffer) - 1) == '/')) {
      GR_JUMP_TRACE;
      urlBuffer = (char *)realloc(urlBuffer, strlen(urlBuffer) + 10 + 1);
      strcpy(urlBuffer + strlen(urlBuffer), "index.html");
    }

    // Interpret '%' character
    std::string urlString(urlBuffer);
    size_t      start = 0, end = 0;

    while ((end = urlString.find_first_of('%', start)) != std::string::npos) {
      GR_JUMP_TRACE;
      size_t len = urlString.length() - end - 1;
      if (urlString[end] == '%' && len >= 1) {
        GR_JUMP_TRACE;
        if (urlString[end + 1] == '%') {
          GR_JUMP_TRACE;
          urlString = urlString.erase(end + 1, 1);
        } else {
          GR_JUMP_TRACE;
          if (len >= 2) {
            GR_JUMP_TRACE;
            unsigned int      specar;
            std::string       hexChar = urlString.substr(end + 1, 2);
            std::stringstream ss;
            ss << std::hex << hexChar.c_str();
            ss >> specar;
            urlString[end] = (char)specar;
            urlString      = urlString.erase(end + 1, 2);
          }
        }
      }
      start = end + 1;
    }
    strcpy(urlBuffer, urlString.c_str());

#ifdef DEBUG_TRACES
    char logBuffer[BUFSIZE];
    snprintf(logBuffer, BUFSIZE,
             "Request : url='%s'  reqType='%d'  param='%s' "
             " requestCookies='%s'  (httpVers=%s "
             "keepAlive=%d zipSupport=%d "
             "closing=%d)\n",
             urlBuffer, requestMethod, requestParams, requestCookies, httpVers, keepAlive, clientSockData->compression,
             closing);
    spdlog::debug(logBuffer);
#endif

    if (multipartContent != nullptr) {
      GR_JUMP_TRACE;
      try {
        // Initialize MPFDParser
        multipartContentParser = new MPFD::Parser();
        multipartContentParser->SetUploadedFilesStorage(MPFD::Parser::StoreUploadedFilesInFilesystem);
        multipartContentParser->SetTempDirForFileUpload(multipartTempDirForFileUpload);
        multipartContentParser->SetMaxCollectedDataLength(multipartMaxCollectedDataLength);
        multipartContentParser->SetContentType(multipartContent);
        GR_JUMP_TRACE;
      } catch (const MPFD::Exception &e) {
        GR_JUMP_TRACE;
        spdlog::debug("WebServer::accept_request -  MPFD::Exception: " + e.GetError());
        delete multipartContentParser;
        multipartContentParser = nullptr;
      }
    }

    // Read request content
    if (requestContentLength) {
      GR_JUMP_TRACE;
      size_t datalen = 0;

      while (datalen < requestContentLength) {
        GR_JUMP_TRACE;
        char   buffer[BUFSIZE];
        size_t requestedLength = (requestContentLength - datalen > BUFSIZE) ? BUFSIZE : requestContentLength - datalen;

        if (mIsSSLEnabled) {
          GR_JUMP_TRACE;
          int r = BIO_gets(clientSockData->bio, buffer, requestedLength + 1); // BUFSIZE);

          switch (SSL_get_error(clientSockData->ssl, r)) {
          case SSL_ERROR_NONE:
            GR_JUMP_TRACE;
            if ((r == 0) || (r == -1)) {
              continue;
            }
            bufLineLen = r;
            break;
          case SSL_ERROR_ZERO_RETURN:
            GR_JUMP_TRACE;
            spdlog::debug("WebServer::accept_request - BIO_gets() "
                          "failed with SSL_ERROR_ZERO_RETURN - 2");
            goto FREE_RETURN_TRUE;
          }
        } else {
          GR_JUMP_TRACE;
          bufLineLen = recvLine(clientSockData->socketId, buffer, requestedLength);
        }

        if (urlencodedForm) {
          GR_JUMP_TRACE;
          if (requestParams == nullptr) {
            GR_JUMP_TRACE;
            requestParams = (char *)malloc((bufLineLen + 1) * sizeof(char));
          } else {
            GR_JUMP_TRACE;
            requestParams = (char *)realloc(requestParams, (datalen + bufLineLen + 1));
          }

          if (requestParams == nullptr) {
            GR_JUMP_TRACE;
            spdlog::debug("WebServer::accept_request -  memory allocation failed");
            break;
          }
          memcpy(requestParams + datalen, buffer, bufLineLen);
          *(requestParams + datalen + bufLineLen) = '\0';
        } else {
          GR_JUMP_TRACE;
          if (multipartContentParser != nullptr && bufLineLen) {
            try {
              multipartContentParser->AcceptSomeData(buffer, bufLineLen);
            } catch (const MPFD::Exception &e) {
              spdlog::debug("WebServer::accept_request -  MPFD::Exception: " + e.GetError());
              break;
            }
          } else {
            GR_JUMP_TRACE;
            if (!payload.size()) {
              try {
                GR_JUMP_TRACE;
                payload.reserve(requestContentLength);
              } catch (std::bad_alloc &e) {
                GR_JUMP_TRACE;
                spdlog::debug("WebServer::accept_request -  "
                              "payload.reserve() failed with "
                              "exception: " +
                              std::string(e.what()));
                break;
              }
            }

            payload.resize(datalen + bufLineLen);
            memcpy(&payload[datalen], buffer, bufLineLen);
          }
        }

        datalen += bufLineLen;
      };
    }

    /* *************************
    /  * processing WebSockets *
    /  *************************/

    if (websocket) {
      GR_JUMP_TRACE;
      // search endpoint
      std::map<std::string, WebSocket *>::iterator it;

      it = webSocketEndPoints.find(urlBuffer);
      if (it != webSocketEndPoints.end()) // FOUND
      {
        GR_JUMP_TRACE;
        WebSocket *webSocket = it->second;
        if (!webSocket->isUsingCompression()) {
          clientSockData->compression = NONE;
        }

        std::string header =
            getHttpWebSocketHeader("101 Switching Protocols", webSocketClientKey, clientSockData->compression == ZLIB);

        if (!httpSend(clientSockData, (const void *)header.c_str(), header.length())) {
          GR_JUMP_TRACE;
          goto FREE_RETURN_TRUE;
        }

        GR_JUMP_TRACE;
        auto *request = new HttpRequest(requestMethod, urlBuffer, requestParams, requestCookies, requestExtraHeaders, requestOrigin,
                                        username, clientSockData, mimeType, &payload, multipartContentParser);

        GR_JUMP_TRACE;
        webSocket->newConnectionRequest(request);

        if (urlBuffer != nullptr) {
          free(urlBuffer);
        }
        if (requestParams != nullptr) {
          free(requestParams);
        }
        if (requestCookies != nullptr) {
          free(requestCookies);
        }
        if (requestOrigin != nullptr) {
          free(requestOrigin);
        }
        if (webSocketClientKey != nullptr) {
          free(webSocketClientKey);
        }
        if (multipartContent != nullptr) {
          free(multipartContent);
        }
        if (multipartContentParser != nullptr) {
          delete multipartContentParser;
        }
        GR_JUMP_TRACE;
        return false;
      } else {
        GR_JUMP_TRACE;
        spdlog::warn("Webserver: Websocket not found '{}'", urlBuffer);

        std::string msg = getNotFoundErrorMsg();
        httpSend(clientSockData, (const void *)msg.c_str(), msg.length());

        goto FREE_RETURN_TRUE;
      }
    }

    /* ********************* */

    bool           fileFound   = false;
    unsigned char *webpage     = nullptr;
    size_t         webpageLen  = 0;
    unsigned char *gzipWebPage = nullptr;
    int            sizeZip     = 0;
    bool           zippedFile  = false;

    GR_JUMP_TRACE;
    HttpRequest request(requestMethod, urlBuffer, requestParams, requestCookies, requestExtraHeaders, requestOrigin, username,
                        clientSockData, mimeType, &payload, multipartContentParser);

    GR_JUMP_TRACE;
    const char *mime = get_mime_type(urlBuffer);
    std::string mimeStr;
    if (mime != nullptr) {
      mimeStr = mime;
    }
    HttpResponse response(mimeStr);

    std::vector<WebRepository *>::const_iterator repo = webRepositories.begin();
    for (; repo != webRepositories.end() && !fileFound && !zippedFile;) {
      GR_JUMP_TRACE;
      if (*repo == NULL) {
        GR_JUMP_TRACE;
        continue;
      }

      GR_JUMP_TRACE;
      fileFound = (*repo)->getFile(&request, &response);
      if (fileFound && response.getForwardedUrl() != "") {
        GR_JUMP_TRACE;
        urlBuffer = (char *)realloc(urlBuffer, (response.getForwardedUrl().size() + 1) * sizeof(char));
        strcpy(urlBuffer, response.getForwardedUrl().c_str());
        request.setUrl(urlBuffer);
        response.forwardTo("");
        repo      = webRepositories.begin();
        fileFound = false;
      } else {
        GR_JUMP_TRACE;
        ++repo;
      }
    }

    if (!fileFound) {
      GR_JUMP_TRACE;
      spdlog::warn("Webserver: page not found: '{}'", urlBuffer);

      std::string msg = getNotFoundErrorMsg();
      httpSend(clientSockData, (const void *)msg.c_str(), msg.length());

      goto FREE_RETURN_TRUE;
    } else {
      GR_JUMP_TRACE;
      --repo;
      response.getContent(&webpage, &webpageLen, &zippedFile);

      if (webpage == nullptr || !webpageLen) {
        std::string msg = getHttpHeader(response.getHttpReturnCodeStr().c_str(), 0, false); // getNoContentErrorMsg();
        httpSend(clientSockData, (const void *)msg.c_str(), msg.length());
        if (webpage != nullptr) {
          (*repo)->freeFile(webpage);
        }
        goto FREE_RETURN_TRUE;
      }

      if (zippedFile) {
        GR_JUMP_TRACE;
        gzipWebPage = webpage;
        sizeZip     = webpageLen;
      }
    }
#ifdef DEBUG_TRACES
    spdlog::debug("Webserver: page found: '{}'", urlBuffer);
#endif

    if ((clientSockData->compression == NONE) && zippedFile) {
      GR_JUMP_TRACE;
      // Need to uncompress
      try {
        if ((int)(webpageLen = nvj_gunzip(&webpage, gzipWebPage, sizeZip)) < 0) {
          spdlog::error("Webserver: gunzip decompression failed !");
          std::string msg = getInternalServerErrorMsg();
          httpSend(clientSockData, (const void *)msg.c_str(), msg.length());
          (*repo)->freeFile(gzipWebPage);
          goto FREE_RETURN_TRUE;
        }
      } catch (...) {
        spdlog::error("Webserver: nvj_gunzip raised an exception");
        std::string msg = getInternalServerErrorMsg();
        httpSend(clientSockData, (const void *)msg.c_str(), msg.length());
        (*repo)->freeFile(gzipWebPage);
        goto FREE_RETURN_TRUE;
      }
    }

    // Need to compress
    if (!zippedFile && (clientSockData->compression == GZIP) && (webpageLen > 2048)) {
      const char *mimetype = response.getMimeType().c_str();
      if (mimetype != nullptr && (strncmp(mimetype, "application", 11) == 0 || strncmp(mimetype, "text", 4) == 0)) {
        try {
          if ((int)(sizeZip = nvj_gzip(&gzipWebPage, webpage, webpageLen)) < 0) {
            spdlog::error("Webserver: gunzip compression failed !");
            std::string msg = getInternalServerErrorMsg();
            httpSend(clientSockData, (const void *)msg.c_str(), msg.length());
            (*repo)->freeFile(webpage);
            goto FREE_RETURN_TRUE;
          } else if ((size_t)sizeZip > webpageLen) {
            sizeZip = 0;
            free(gzipWebPage);
          }
        } catch (...) {
          spdlog::error("Webserver: nvj_gzip raised an exception");
          std::string msg = getInternalServerErrorMsg();
          httpSend(clientSockData, (const void *)msg.c_str(), msg.length());
          (*repo)->freeFile(webpage);
          goto FREE_RETURN_TRUE;
        }
      }
    }

    if (keepAlive && (--nbFileKeepAlive <= 0)) { // GLSR aqui eu havia trocado para ==
      closing = true;
    }

    if (sizeZip > 0 && (clientSockData->compression == GZIP)) {
      std::string header =
          getHttpHeader(response.getHttpReturnCodeStr().c_str(), sizeZip, keepAlive, nullptr, true, &response);
      if (!httpSend(clientSockData, (const void *)header.c_str(), header.length()) ||
          !httpSend(clientSockData, (const void *)gzipWebPage, sizeZip)) {
        spdlog::error("Webserver: httpSend failed sending the zipped page: {}- err: {}", urlBuffer, strerror(errno));
        closing = true;
      }
    } else {
      std::string header =
          getHttpHeader(response.getHttpReturnCodeStr().c_str(), webpageLen, keepAlive, nullptr, false, &response);
      if (!httpSend(clientSockData, (const void *)header.c_str(), header.length()) ||
          !httpSend(clientSockData, (const void *)webpage, webpageLen)) {
        spdlog::error("Webserver: httpSend failed sending the page: {}- err: {}", urlBuffer, strerror(errno));
        closing = true;
      }
    }

    if (sizeZip > 0 && !zippedFile) // cas compression = double desalloc
    {
      free(gzipWebPage);
      (*repo)->freeFile(webpage);
    } else if ((clientSockData->compression == NONE) && zippedFile) // cas décompression = double desalloc
    {
      free(webpage);
      (*repo)->freeFile(gzipWebPage);
    } else {
      (*repo)->freeFile(webpage);
    }
  } while (keepAlive && !closing && !exiting);

/////////////////
FREE_RETURN_TRUE:

  if (urlBuffer != nullptr) {
    free(urlBuffer);
  }
  if (requestParams != nullptr) {
    free(requestParams);
  }
  if (requestCookies != nullptr) {
    free(requestCookies);
  }
  if (requestOrigin != nullptr) {
    free(requestOrigin);
  }
  if (webSocketClientKey != nullptr) {
    free(webSocketClientKey);
  }
  if (multipartContent != nullptr) {
    free(multipartContent);
  }
  if (multipartContentParser != nullptr) {
    delete multipartContentParser;
  }

  return true;
}

/***********************************************************************
 * httpSend - send data from the socket
 * @param client - the ClientSockData to use
 * @param buf - the data
 * @param len - the data length
 * \return false if it's failed
 ***********************************************************************/

bool WebServer::httpSend(ClientSockData *client, const void *buf, size_t len) {
  GR_JUMP_TRACE;
  //  pthread_mutex_lock( &client->client_mutex );

  if (!client->socketId) {
    // pthread_mutex_unlock( &client->client_mutex );
    return false;
  }

  bool           useSSL      = client->bio != nullptr;
  size_t         totalSent   = 0;
  int            sent        = 0;
  unsigned char *buffer_left = (unsigned char *)buf;

  fd_set writeset;
  FD_ZERO(&writeset);
  FD_SET(client->socketId, &writeset);
  struct timeval tv;
  tv.tv_sec  = 10;
  tv.tv_usec = 0;
  int result;

  do {
    if (useSSL) {
      sent = BIO_write(client->bio, buffer_left, len - totalSent);
    } else {
      sent = sendCompat(client->socketId, buffer_left, len - totalSent, MSG_NOSIGNAL);
    }

    if (sent < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || (useSSL && BIO_should_retry(client->bio))) {
        spdlog::error("Webserver: send buffer full, retrying in 1 second");
        sleep(1);

        /* retry to send data a second time before returning a failure to caller */
        if (useSSL) {
          sent = BIO_write(client->bio, buffer_left, len - totalSent);
        } else {
          result = select(client->socketId + 1, nullptr, &writeset, nullptr, &tv);

          if ((result <= 0) || (!FD_ISSET(client->socketId, &writeset))) {
            return false;
          }

          sent = sendCompat(client->socketId, buffer_left, len - totalSent, MSG_NOSIGNAL);
        }

        if (sent < 0) {
          /* this is the second time it failed, no need to be more stubborn */
          return false;
        } else {
          /* retry succeeded, don't forget to update counters and buffer left to send */
          totalSent += (size_t)sent;
          buffer_left += sent;
        }
      } else {
        usleep(50);
        continue;
      }
    } else {
      totalSent += (size_t)sent;
      buffer_left += sent;
    }
  } while (sent >= 0 && totalSent != len);

  if (useSSL) {
    BIO_flush(client->bio);
  }

  //  pthread_mutex_unlock( &client->client_mutex );

  return totalSent == len;
}

/***********************************************************************
 * fatalError:  Print out a system error and exit
 * @param s - error message
 ***********************************************************************/

void WebServer::fatalError(const char *s) {
  GR_JUMP_TRACE;
  spdlog::error("{}: {}", s, strerror(errno));
  ::exit(1);
}

/***********************************************************************
 * get_mime_type: return valid mime_type using filename's extension
 * @param name - filename
 * \return mime_type or NULL is no found
 ***********************************************************************/

const char *WebServer::get_mime_type(const char *name) {
  GR_JUMP_TRACE;
  char *ext = strrchr(const_cast<char *>(name), '.');
  if (!ext) {
    return nullptr;
  }

  char     extLowerCase[6];
  unsigned i = 0;
  for (; i < 5 && i < strlen(ext); i++) {
    extLowerCase[i] = ext[i];
    if ((extLowerCase[i] >= 'A') && (extLowerCase[i] <= 'Z')) {
      extLowerCase[i] += 'a' - 'A';
    }
  }
  extLowerCase[i] = '\0';

  if (strcmp(extLowerCase, ".html") == 0 || strcmp(extLowerCase, ".htm") == 0) {
    return "text/html";
  }
  if (strcmp(extLowerCase, ".js") == 0) {
    return "application/javascript";
  }
  if (strcmp(extLowerCase, ".json") == 0) {
    return "application/json";
  }
  if (strcmp(extLowerCase, ".xml") == 0) {
    return "application/xml";
  }
  if (strcmp(extLowerCase, ".jpg") == 0 || strcmp(extLowerCase, ".jpeg") == 0) {
    return "image/jpeg";
  }
  if (strcmp(extLowerCase, ".gif") == 0) {
    return "image/gif";
  }
  if (strcmp(extLowerCase, ".png") == 0) {
    return "image/png";
  }
  if (strcmp(extLowerCase, ".css") == 0) {
    return "text/css";
  }
  if (strcmp(extLowerCase, ".txt") == 0) {
    return "text/plain";
  }
  if (strcmp(extLowerCase, ".svg") == 0 || strcmp(extLowerCase, ".svgz") == 0) {
    return "image/svg+xml";
  }
  if (strcmp(extLowerCase, ".cache") == 0) {
    return "text/cache-manifest";
  }

  // ----------------------------------------------------------------------
  // Fontes
  // ----------------------------------------------------------------------
  if (strcmp(extLowerCase, ".otf") == 0) {
    return "font/otf";
  }
  if (strcmp(extLowerCase, ".eot") == 0) {
    return "font/eot";
  }
  if (strcmp(extLowerCase, ".ttf") == 0) {
    return "font/ttf";
  }
  if (strcmp(extLowerCase, ".woff") == 0) {
    return "font/woff";
  }
  if (strcmp(extLowerCase, ".woff2") == 0) {
    return "font/woff2";
  }

  if (strcmp(extLowerCase, ".au") == 0) {
    return "audio/basic";
  }
  if (strcmp(extLowerCase, ".wav") == 0) {
    return "audio/wav";
  }
  if (strcmp(extLowerCase, ".avi") == 0) {
    return "video/x-msvideo";
  }
  if (strcmp(extLowerCase, ".mpeg") == 0 || strcmp(extLowerCase, ".mpg") == 0) {
    return "video/mpeg";
  }
  if (strcmp(extLowerCase, ".mp3") == 0) {
    return "audio/mpeg";
  }
  if (strcmp(extLowerCase, ".csv") == 0) {
    return "text/csv";
  }
  if (strcmp(extLowerCase, ".mp4") == 0) {
    return "application/mp4";
  }
  if (strcmp(extLowerCase, ".bin") == 0) {
    return "application/octet-stream";
  }
  if (strcmp(extLowerCase, ".doc") == 0 || strcmp(extLowerCase, ".docx") == 0) {
    return "application/msword";
  }
  if (strcmp(extLowerCase, ".pdf") == 0) {
    return "application/pdf";
  }
  if (strcmp(extLowerCase, ".ps") == 0 || strcmp(extLowerCase, ".eps") == 0 || strcmp(extLowerCase, ".ai") == 0) {
    return "application/postscript";
  }
  if (strcmp(extLowerCase, ".tar") == 0) {
    return "application/x-tar";
  }
  if (strcmp(extLowerCase, ".h264") == 0) {
    return "video/h264";
  }
  if (strcmp(extLowerCase, ".dv") == 0) {
    return "video/dv";
  }
  if (strcmp(extLowerCase, ".qt") == 0 || strcmp(extLowerCase, ".mov") == 0) {
    return "video/quicktime";
  }

  return nullptr;
}

/***********************************************************************
 * getHttpHeader: generate HTTP header
 * @param messageType - client socket descriptor
 * @param len - HTTP message type
 * @param keepAlive
 * @param zipped - true is content will be compressed
 * @param response - the HttpResponse
 * \return result of send function (successfull: >=0, otherwise <0)
 ***********************************************************************/

std::string WebServer::getHttpHeader(const char *messageType, const size_t len, const bool keepAlive,
                                     const char *authBearerAdditionalHeaders, const bool zipped,
                                     HttpResponse *response) {
  GR_JUMP_TRACE;
  char      timeBuf[200];
  time_t    rawtime;
  struct tm timeinfo;

  std::string header = "HTTP/1.1 " + std::string(messageType) + std::string("\r\n");
  time(&rawtime);
  gmtime_r(&rawtime, &timeinfo);
  strftime(timeBuf, 200, "Date: %a, %d %b %Y %H:%M:%S GMT", &timeinfo);
  header += std::string(timeBuf) + "\r\n";

  header += webServerName + "\r\n";

  if (strncmp(messageType, "401", 3) == 0) {
    if (authBearerAdditionalHeaders) {
      header += std::string("WWW-Authenticate: Bearer ");
      header += authBearerAdditionalHeaders;
      header += "\r\n";
    } else {
      header += std::string("WWW-Authenticate: Basic realm=\"Restricted area: "
                            "please enter Login/Password\"\r\n");
    }
  }

  if (response != nullptr) {
    if (response->isCORS()) {
      header += "Access-Control-Allow-Origin: " + response->getCORSdomain() + "\r\n";
      if (response->isCORSwithCredentials()) {
        header += "Access-Control-Allow-Credentials: true\r\n";
      } else {
        header += "Access-Control-Allow-Credentials: false\r\n";
      }
    }

    header += response->getSpecificHeaders();

    std::vector<std::string> &cookies = response->getCookies();
    for (const auto &cookie : cookies) {
      header += "Set-Cookie: " + cookie + "\r\n";
      // spdlog::debug( "Cabeçalho de cookie: {}", cookie );
    }
  }

  header += "Accept-Ranges: bytes\r\n";

  if (keepAlive) {
    header += "Connection: Keep-Alive\r\n";
  } else {
    header += "Connection: close\r\n";
  }

  std::string mimetype = "text/html";
  if (response != nullptr) {
    mimetype = response->getMimeType();
  }
  header += "Content-Type: " + mimetype + "\r\n";

  if (zipped) {
    header += "Content-Encoding: gzip\r\n";
  }

  if (len) {
    std::stringstream lenSS;
    lenSS << len;
    header += "Content-Length: " + lenSS.str() + "\r\n";
  }

  header += "\r\n";

  return header;
}

/**********************************************************************
 * getNoContentErrorMsg: send a 204 No Content Message
 * \return the http message to send
 ***********************************************************************/

std::string WebServer::getNoContentErrorMsg() {
  GR_JUMP_TRACE;
  std::string header = getHttpHeader("204 No Content", 0, false);

  return header;
}

/**********************************************************************
 * sendBadRequestError: send a 400 Bad Request Message
 * \return the http message to send
 ***********************************************************************/

std::string WebServer::getBadRequestErrorMsg() {
  GR_JUMP_TRACE;

  const std::string errorMessage = R"(
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Bad Request!</title>
  </head>
  <body>
    <h1>Error 400: Bad Request!</h1>
    <p>
      Your browser sent a request that this server could not understand.
    </p>
  </body>
</html>
)";

  std::string header = getHttpHeader("400 Bad Request", errorMessage.length(), false);

  return header + errorMessage;
}

/***********************************************************************
 * sendNotFoundError: send a 404 not found error message
 * \return the http message to send
 ***********************************************************************/

std::string WebServer::getNotFoundErrorMsg() {
  GR_JUMP_TRACE;

  const std::string errorMessage = R"(
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Object not found!</title>
  </head>
  <body>
    <h1>Error 404: Object not found!</h1>
    <p>
      The requested URL was not found on this server.
      If you entered the URL manually please check your spelling and try again.
    </p>
  </body>
</html>
)";

  std::string header = getHttpHeader("404 Not Found", errorMessage.length(), false);

  return header + errorMessage;
}

/***********************************************************************
 * sendInternalServerError: send a 500 Internal Server Error
 * \return the http message to send
 ***********************************************************************/

std::string WebServer::getInternalServerErrorMsg() {
  GR_JUMP_TRACE;

  const std::string errorMessage = R"(
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Internal Server Error!</title>
  </head>
  <body>
    <h1>Error 500: Internal Server Error!</h1>
    <p>
      Something happens.
      If you entered the URL manually please check your spelling and try again.
    </p>
  </body>
</html>
)";

  std::string header = getHttpHeader("500 Internal Server Error", errorMessage.length(), false);

  return header + errorMessage;
}

/***********************************************************************
 * sendInternalServerError: send a 501 Method Not Implemented
 * \return the http message to send
 ***********************************************************************/

std::string WebServer::getNotImplementedErrorMsg() {
  GR_JUMP_TRACE;

  const std::string errorMessage = R"(
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Cannot process request!</title>
  </head>
  <body>
    <h1>Error 501: Cannot process request!</h1>
    <p>
      The server does not support the action requested by the browser.
      If you entered the URL manually please check your spelling and try again.
    </p>
  </body>
</html>
)";

  std::string header = getHttpHeader("501 Method Not Implemented", errorMessage.length(), false);

  return header + errorMessage;
}

/***********************************************************************
 * init: Initialize server listening socket
 * \return Port server used
 ***********************************************************************/

u_short WebServer::init() {
  GR_JUMP_TRACE;
  // Build SSL context
  if (mIsSSLEnabled) {
    initialize_ctx(sslCertFile.c_str(), sslCaFile.c_str(), sslCertPwd.c_str());
  }

  struct addrinfo  hints;
  struct addrinfo *result, *rp;

  nbServerSock = 0;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family    = AF_UNSPEC;   /* Allow IPv4 or IPv6 */
  hints.ai_socktype  = SOCK_STREAM; /* TCP socket */
  hints.ai_flags     = AI_PASSIVE;  /* For wildcard IP address */
  hints.ai_protocol  = IPPROTO_TCP;
  hints.ai_canonname = nullptr;
  hints.ai_addr      = nullptr;
  hints.ai_next      = nullptr;

  char portStr[10];
  snprintf(portStr, 10, "%d", tcpPort);

  if (getaddrinfo(nullptr, portStr, &hints, &result) != 0) {
    fatalError("WebServer : getaddrinfo error ");
  }

  for (rp = result; rp != nullptr && nbServerSock < sizeof(server_sock) / sizeof(int); rp = rp->ai_next) {
    if ((server_sock[nbServerSock] = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1) {
      continue;
    }

    setSocketReuseAddr(server_sock[nbServerSock]);

    if (device.length()) {
#ifndef LINUX
      spdlog::warn("WebServer: HttpdDevice parameter will be ignored on your system");
#else
      setSocketBindToDevice(server_sock[nbServerSock], device.c_str());
#endif
    }

    if (rp->ai_family == PF_INET && disableIpV4) {
      continue;
    }

    if (rp->ai_family == PF_INET6) {
      if (disableIpV6) {
        continue;
      }
#if defined(IPV6_V6ONLY)

      // Disable IPv4 mapped addresses.
      setSocketIp6Only(server_sock[nbServerSock]);
#else
      spdlog::warn("WebServer: Cannot set IPV6_V6ONLY socket option.  Closing IPv6 socket.");
      close(server_sock[nbServerSock]);
      continue;
#endif
    }
    if (bind(server_sock[nbServerSock], rp->ai_addr, rp->ai_addrlen) == 0) {
      if (listen(server_sock[nbServerSock], 128) >= 0) {
        nbServerSock++; /* Success */
        continue;
      }
    }

    close(server_sock[nbServerSock]);
  }
  freeaddrinfo(result); /* No longer needed */

  if (nbServerSock == 0) {
    fatalError("WebServer : Init Failed ! (nbServerSock == 0)");
  }

  return (tcpPort);
}

/***********************************************************************
 * exit: Stop http server
 ***********************************************************************/

void WebServer::exit() {
  GR_JUMP_TRACE;
  pthread_mutex_lock(&clientsQueue_mutex);
  exiting = true;

  for (auto &webSocketEndPoint : webSocketEndPoints) {
    webSocketEndPoint.second->removeAllClients();
  }

  while (nbServerSock > 0) {
    shutdown(server_sock[--nbServerSock], 2);
    close(server_sock[nbServerSock]);
  }
  pthread_mutex_unlock(&clientsQueue_mutex);

  if( mIsSSLEnabled ) {
    SSL_CTX_free(sslCtx);
  }
}

/***********************************************************************
 * password_cb
 ************************************************************************/

int WebServer::password_cb(char *buf, int num, int /*rwflag*/, void * /*userdata*/) {
  GR_JUMP_TRACE;
  if ((size_t)num < strlen(certpass) + 1) {
    return (0);
  }

  strcpy(buf, certpass);
  return (strlen(certpass));
}

/***********************************************************************
 * verify_callback:
 ************************************************************************/

int WebServer::verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
  GR_JUMP_TRACE;
  char  buf[256];
  X509 *err_cert;
  int   err, depth;

  err_cert = X509_STORE_CTX_get_current_cert(ctx);
  err      = X509_STORE_CTX_get_error(ctx);
  depth    = X509_STORE_CTX_get_error_depth(ctx);

  X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

  /* Catch a too long certificate chain */
  if (depth > verify_depth) {
    preverify_ok = 0;
    err          = X509_V_ERR_CERT_CHAIN_TOO_LONG;
    X509_STORE_CTX_set_error(ctx, err);
  }
  if (!preverify_ok) {
    char buftmp[300];
    snprintf(buftmp, 300, "X509_verify_cert error: num=%d:%s:depth=%d:%s", err, X509_verify_cert_error_string(err),
             depth, buf);
  }

  /*
   * At this point, err contains the last verification error. We can use
   * it for something special
   */
  if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
    X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, 256);
    char buftmp[300];
    snprintf(buftmp, 300, "X509_verify_cert error: issuer= %s", buf);
  }

  return 1;
}

/***********************************************************************
 * initialize_ctx:
 ************************************************************************/

void WebServer::initialize_ctx(const char *certfile, const char *cafile, const char *password) {
  GR_JUMP_TRACE;
  /* Global system initialization*/
  if(!sslCtx) {
    SSL_library_init();
    SSL_load_error_strings();
  }

  /* Create our context*/
  sslCtx = SSL_CTX_new(SSLv23_method());

  /* Load our keys and certificates*/
  if (!(SSL_CTX_use_certificate_chain_file(sslCtx, certfile))) {
    spdlog::error("OpenSSL error: Can't read certificate file");
    ::exit(1);
  }

  certpass = (char *)password;
  SSL_CTX_set_default_passwd_cb(sslCtx, WebServer::password_cb);
  if (!(SSL_CTX_use_PrivateKey_file(sslCtx, certfile, SSL_FILETYPE_PEM))) {
    spdlog::error("OpenSSL error: Can't read key file");
    ::exit(1);
  }

  SSL_CTX_set_session_id_context(sslCtx, (const unsigned char *)&s_server_session_id_context,
                                 sizeof s_server_session_id_context);

  if (mIsAuthPeerSSL) {
    if (!(SSL_CTX_load_verify_locations(sslCtx, cafile, nullptr))) {
      spdlog::error("OpenSSL error: Can't read CA list");
      ::exit(1);
    }

    SSL_CTX_set_verify(sslCtx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, verify_callback);

    SSL_CTX_set_verify_depth(sslCtx, verify_depth + 1);
  }
}

/**********************************************************************/

bool WebServer::isAuthorizedDN(const std::string str) // GLSR FIXME
{
  GR_JUMP_TRACE;
  bool res = false;
  for (std::vector<std::string>::const_iterator i = authDnList.begin(); i != authDnList.end() && !res; ++i) {
    res = (*i == str);
  }
  return res;
}

/**********************************************************************/

void WebServer::poolThreadProcessing() {
  GR_JUMP_TRACE;
  X509           *peer           = nullptr;
  bool            authSSL        = false;
  ClientSockData *clientSockData = nullptr;

  sigset_t sigset;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGPIPE);
  sigprocmask(SIG_BLOCK, &sigset, nullptr);

  while (!exiting) {
    pthread_mutex_lock(&clientsQueue_mutex);

    while (clientsQueue.empty() && !exiting) {
      pthread_cond_wait(&clientsQueue_cond, &clientsQueue_mutex);
    }

    if (exiting) {
      pthread_mutex_unlock(&clientsQueue_mutex);
      break;
    }

    // clientsQueue is not empty
    clientSockData = clientsQueue.front();
    clientsQueue.pop();

    if (mIsSSLEnabled) {
      BIO *bio = nullptr;

      if (!(bio = BIO_new_socket(clientSockData->socketId, BIO_NOCLOSE))) {
        spdlog::debug("BIO_new_socket failed !");
        freeClientSockData(clientSockData);
        pthread_mutex_unlock(&clientsQueue_mutex);
        continue;
      }

      if (!(clientSockData->ssl = SSL_new(sslCtx))) {
        spdlog::debug("SSL_new failed !");
        freeClientSockData(clientSockData);
        pthread_mutex_unlock(&clientsQueue_mutex);
        continue;
      }

      SSL_set_bio(clientSockData->ssl, bio, bio);

      ERR_clear_error();

      // SIGSEGV
      if (SSL_accept(clientSockData->ssl) <= 0) {
        const char *sslmsg = ERR_reason_error_string(ERR_get_error());
        std::string msg    = "SSL accept error ";
        if (sslmsg != nullptr) {
          msg += ": " + std::string(sslmsg);
        }
        spdlog::debug(msg);
        freeClientSockData(clientSockData);
        pthread_mutex_unlock(&clientsQueue_mutex);
        continue;
      }

      if (mIsAuthPeerSSL) {
        if ((peer = SSL_get_peer_certificate(clientSockData->ssl)) != nullptr) {
          if (SSL_get_verify_result(clientSockData->ssl) == X509_V_OK) {
            // The clientSockData sent a certificate which verified OK
            char *str = X509_NAME_oneline(X509_get_subject_name(peer), nullptr, 0);

            if ((authSSL = isAuthorizedDN(str)) == true) {
              authSSL                = true;
              clientSockData->peerDN = new std::string(str);
              updatePeerDnHistory(*(clientSockData->peerDN));
            }

            free(str);
            X509_free(peer);
          }
        }
      } else {
        authSSL = true;
      }

      //----------------------------------------------------------------------------------------------------------------

      BIO *ssl_bio = nullptr;

      clientSockData->bio = BIO_new(BIO_f_buffer());
      ssl_bio             = BIO_new(BIO_f_ssl());
      BIO_set_ssl(ssl_bio, clientSockData->ssl, BIO_CLOSE);
      BIO_push(clientSockData->bio, ssl_bio);

      if (mIsAuthPeerSSL && !authSSL) {
        std::string msg = getHttpHeader("403 Forbidden clientSockData Certificate Required", 0, false);
        httpSend(clientSockData, (const void *)msg.c_str(), msg.length());
        freeClientSockData(clientSockData);
        pthread_mutex_unlock(&clientsQueue_mutex);
        continue;
      }
    }

    pthread_mutex_unlock(&clientsQueue_mutex);

    if (accept_request(clientSockData, authSSL)) {
      freeClientSockData(clientSockData);
    }
  }
  pthread_mutex_lock(&clientsQueue_mutex);
  exitedThread++;
  pthread_mutex_unlock(&clientsQueue_mutex);
}

/***********************************************************************
 * initPoolThreads:
 ************************************************************************/

void WebServer::initPoolThreads() {
  GR_JUMP_TRACE;
  pthread_t newthread;
  for (unsigned i = 0; i < threadsPoolSize; i++) {
    create_thread(&newthread, WebServer::startPoolThread, static_cast<void *>(this));
    usleep(500);
  }
  exitedThread = 0;
}

/***********************************************************************
 * startThread: Launch http server
 * @param p - port server to use. If port is 0, port value will be modified
 *                 dynamically.
 * \return NULL
 ************************************************************************/

void *WebServer::startThread(void *t) {
  GR_JUMP_TRACE;
  static_cast<WebServer *>(t)->threadProcessing();
  pthread_exit(nullptr);
  return nullptr;
}

void WebServer::threadProcessing() {
  GR_JUMP_TRACE;
  int client_sock = 0;

  exiting      = false;
  exitedThread = 0;

  struct sockaddr_storage clientAddress;
  socklen_t               clientAddressLength = sizeof(clientAddress);

  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGPIPE);
  sigprocmask(SIG_BLOCK, &set, nullptr);

  ushort port = init();

  initPoolThreads();
  httpdAuth = authLoginPwdList.size();

  spdlog::info("WebServer listen on port {}", port);

  struct pollfd *pfd;
  if ((pfd = (pollfd *)malloc(nbServerSock * sizeof(struct pollfd))) == nullptr) {
    fatalError("WebServer : malloc error ");
  }

  unsigned idx;
  int      status;

  for (idx = 0; idx < nbServerSock; idx++) {
    pfd[idx].fd      = server_sock[idx];
    pfd[idx].events  = POLLIN;
    pfd[idx].revents = 0;
  }

  for (; !exiting;) {
    do {
      status = poll(pfd, nbServerSock, 500);
    } while ((status < 0) && (errno == EINTR) && !exiting);

    for (idx = 0; idx < nbServerSock && !exiting; idx++) {

      if (!(pfd[idx].revents & POLLIN)) {
        continue;
      }

      client_sock = accept(pfd[idx].fd, (struct sockaddr *)&clientAddress, &clientAddressLength);

      IpAddress webClientAddr;

      if (clientAddress.ss_family == AF_INET) {
        webClientAddr.ipversion = 4;
        webClientAddr.ip.v4     = ((struct sockaddr_in *)&clientAddress)->sin_addr.s_addr;
      }

      if (clientAddress.ss_family == AF_INET6) {
        webClientAddr.ipversion = 6;
        webClientAddr.ip.v6     = ((struct sockaddr_in6 *)&clientAddress)->sin6_addr;
      }

      if (exiting) {
        close(pfd[idx].fd);
        break;
      };

      if (hostsAllowed.size() && !isIpBelongToIpNetwork(webClientAddr, hostsAllowed)) {
        shutdown(client_sock, SHUT_RDWR);
        close(client_sock);
        continue;
      }

      //

      updatePeerIpHistory(webClientAddr);
      if (client_sock == -1) {
        spdlog::error("WebServer : An error occurred when attempting to access the socket (accept == -1)");
      } else {
        if (socketTimeoutInSecond) {
          if (!setSocketSndRcvTimeout(client_sock, socketTimeoutInSecond, 0)) {
            spdlog::error("WebServer : setSocketSndRcvTimeout error - {}", strerror(errno));
          }
        }
        if (!setSocketNoSigpipe(client_sock)) {
          spdlog::error("WebServer : setSocketNoSigpipe error - {}", strerror(errno));
        }

        auto *client        = (ClientSockData *)malloc(sizeof(ClientSockData));
        client->socketId    = client_sock;
        client->ip          = webClientAddr;
        client->compression = NONE;
        client->ssl         = nullptr;
        client->bio         = nullptr;
        client->peerDN      = nullptr;
        // pthread_mutex_init ( &client->client_mutex, NULL );

        pthread_mutex_lock(&clientsQueue_mutex);
        clientsQueue.push(client);
        pthread_mutex_unlock(&clientsQueue_mutex);
        pthread_cond_signal(&clientsQueue_cond);
      }
    }
  }

  while (exitedThread != threadsPoolSize) {
    pthread_cond_broadcast(&clientsQueue_cond);
    usleep(500);
  }

  // Exiting...
  free(pfd);

  pthread_mutex_destroy(&clientsQueue_mutex);
}

/***********************************************************************/

void WebServer::closeSocket(ClientSockData *clientSockData) {
  GR_JUMP_TRACE;
  if (clientSockData->ssl) {
    int n = SSL_shutdown(clientSockData->ssl);
    if (!n) {
      shutdown(clientSockData->socketId, 1);
      SSL_shutdown(clientSockData->ssl);
    }
  }
  shutdown(clientSockData->socketId, SHUT_RDWR);
  close(clientSockData->socketId);
  clientSockData->socketId = 0;
}

/***********************************************************************
* base64_decode & base64_encode
  thanks to  René Nyffenegger rene.nyffenegger@adp-gmbh.ch for his
  public implementation of this algorithm
*
************************************************************************/

std::string WebServer::base64_decode(const std::string &encoded_string) {
  GR_JUMP_TRACE;

  int           in_len = encoded_string.size();
  int           i      = 0;
  int           j      = 0;
  int           in_    = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string   ret;

  while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_];
    in_++;
    if (i == 4) {
      for (i = 0; i < 4; i++) {
        char_array_4[i] = base64_chars.find(char_array_4[i]);
      }

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++) {
        ret += char_array_3[i];
      }
      i = 0;
    }
  }

  if (i) {
    for (j = i; j < 4; j++) {
      char_array_4[j] = 0;
    }

    for (j = 0; j < 4; j++) {
      char_array_4[j] = base64_chars.find(char_array_4[j]);
    }

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) {
      ret += char_array_3[j];
    }
  }

  return ret;
}

std::string WebServer::base64_encode(unsigned char const *bytes_to_encode, unsigned int in_len) {
  GR_JUMP_TRACE;
  std::string   ret;
  int           i = 0;
  int           j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];

  while (in_len--) {
    char_array_3[i++] = *(bytes_to_encode++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for (i = 0; (i < 4); i++) {
        ret += base64_chars[char_array_4[i]];
      }
      i = 0;
    }
  }

  if (i) {
    for (j = i; j < 3; j++) {
      char_array_3[j] = '\0';
    }

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++) {
      ret += base64_chars[char_array_4[j]];
    }

    while ((i++ < 3)) {
      ret += '=';
    }
  }
  return ret;
}

/***********************************************************************
 * SHA1_encode: Generate the SHA1 encoding
 * @param input - the string to encode
 * \return the encoded string
 ************************************************************************/
std::string WebServer::SHA1_encode(const std::string &input) {
  GR_JUMP_TRACE;
  std::string hash;
  SHA_CTX     context;
  SHA1_Init(&context);
  SHA1_Update(&context, &input[0], input.size());
  hash.resize(160 / 8);
  SHA1_Final((unsigned char *)&hash[0], &context);
  return hash;
}

/***********************************************************************
 * generateWebSocketServerKey: Generate the websocket server key
 * @param webSocketKey - the websocket client key.
 * \return the websocket server key
 ************************************************************************/
std::string WebServer::generateWebSocketServerKey(std::string webSocketKey) {
  GR_JUMP_TRACE;
  std::string sha1Key = SHA1_encode(webSocketKey + webSocketMagicString);
  return base64_encode(reinterpret_cast<const unsigned char *>(sha1Key.c_str()), sha1Key.length());
}

/***********************************************************************
 * getHttpWebSocketHeader: generate HTTP header
 * @param messageType - client socket descriptor
 * \return the header
 ***********************************************************************/

std::string WebServer::getHttpWebSocketHeader(const char *messageType, const char *webSocketClientKey,
                                              const bool webSocketDeflate) {
  GR_JUMP_TRACE;
  char      timeBuf[200];
  time_t    rawtime;
  struct tm timeinfo;

  std::string header = "HTTP/1.1 " + std::string(messageType) + std::string("\r\n");
  header += "Upgrade: websocket\r\n";
  header += "Connection: Upgrade\r\n";

  time(&rawtime);
  gmtime_r(&rawtime, &timeinfo);
  strftime(timeBuf, 200, "Date: %a, %d %b %Y %H:%M:%S GMT", &timeinfo);
  header += std::string(timeBuf) + "\r\n";

  header += webServerName + "\r\n";

  header += "Sec-WebSocket-Accept: " + generateWebSocketServerKey(webSocketClientKey) + "\r\n";

  if (webSocketDeflate) {
    header += "Sec-WebSocket-Extensions: permessage-deflate\r\n"; // x-webkit-deflate-frame
  }

  header += "\r\n";

  return header;
}

/***********************************************************************/
