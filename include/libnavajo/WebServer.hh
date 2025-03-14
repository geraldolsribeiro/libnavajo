//********************************************************
/**
 * @file  WebServer.hh
 *
 * @brief WebServer
 *
 * @author T.Descombes (thierry.descombes@gmail.com)
 *
 * @version 1
 * @date 19/02/15
 */
//********************************************************

#ifndef WEBSERVER_HH_
#define WEBSERVER_HH_

#include <cstdio>
#include <sys/types.h>
#ifdef LINUX
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <map>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <queue>
#include <string>

#include "libnavajo/IpAddress.hh"
#include "libnavajo/LogRecorder.hh"
#include "libnavajo/WebRepository.hh"
#include "libnavajo/nvjThread.h"

class WebSocket;
class WebServer {
  pthread_t    threadWebServer;
  SSL_CTX     *sslCtx;
  int          s_server_session_id_context;
  static char *certpass;

  int (*tokDecodeCallback)(const std::string &tokb64, std::string &secret, std::string &decoded);
  time_t (*authBearTokDecExpirationCb)(std::string &tokenDecoded);
  int (*authBearTokDecScopesCb)(const std::string &tokenDecoded, const std::string &resourceUrl, std::string &errDescr);
  std::string                  authBearerRealm;
  bool                         authBearerEnabled;
  std::string                  tokDecodeSecret;
  std::queue<ClientSockData *> clientsQueue;
  pthread_cond_t               clientsQueue_cond;
  pthread_mutex_t              clientsQueue_mutex;

  void       initialize_ctx(const char *certfile, const char *cafile, const char *password);
  static int password_cb(char *buf, int num, int rwflag, void *userdata);

  bool isUserAllowed(const std::string &logpassb64, std::string &username);
  bool isTokenAllowed(const std::string &tokb64, const std::string &resourceUrl, std::string &respHeader);
  bool isAuthorizedDN(const std::string str); // GLSR FIXME

  size_t             recvLine(int client, char *bufLine, size_t);
  bool               accept_request(ClientSockData *clientSockData, bool authSSL);
  void               fatalError(const char *);
  static std::string getHttpHeader(const char *messageType, const size_t len = 0, const bool keepAlive = true,
                                   const char *authBearerAdditionalHeaders = nullptr, const bool zipped = false,
                                   HttpResponse *response = nullptr);
  static const char *get_mime_type(const char *name);
  u_short            init();

  static std::string getNoContentErrorMsg();
  static std::string getBadRequestErrorMsg();
  static std::string getNotFoundErrorMsg();
  static std::string getInternalServerErrorMsg();
  static std::string getNotImplementedErrorMsg();

  void                initPoolThreads();
  inline static void *startPoolThread(void *t) {
    static_cast<WebServer *>(t)->poolThreadProcessing();
    pthread_exit(nullptr);
    return nullptr;
  };
  void poolThreadProcessing();

  bool httpdAuth;

  volatile bool   exiting;
  volatile size_t exitedThread;
  volatile int    server_sock[3];
  volatile size_t nbServerSock;

  const static char authStr[];
  const static char authBearerStr[];

  std::map<std::string, time_t> usersAuthHistory;
  pthread_mutex_t               usersAuthHistory_mutex;
  std::map<std::string, time_t> tokensAuthHistory;
  pthread_mutex_t               tokensAuthHistory_mutex;
  std::map<IpAddress, time_t>   peerIpHistory;
  std::map<std::string, time_t> peerDnHistory;
  pthread_mutex_t               peerDnHistory_mutex;
  void                          updatePeerIpHistory(IpAddress &);
  void                          updatePeerDnHistory(std::string);
  static int                    verify_callback(int preverify_ok, X509_STORE_CTX *ctx);
  static const int              verify_depth;

  static void *startThread(void *);
  void         threadProcessing();
  void         exit();

  static std::string webServerName;
  volatile bool      disableIpV4, disableIpV6;
  volatile ushort    socketTimeoutInSecond;
  volatile ushort    tcpPort;
  volatile size_t    threadsPoolSize;
  std::string        device;

  std::string multipartTempDirForFileUpload;
  long        multipartMaxCollectedDataLength;

  bool                               mIsSSLEnabled;
  std::string                        sslCertFile, sslCaFile, sslCertPwd;
  std::vector<std::string>           authLoginPwdList;
  bool                               mIsAuthPeerSSL;
  std::vector<std::string>           authDnList;
  std::vector<IpNetwork>             hostsAllowed;
  std::vector<WebRepository *>       webRepositories;
  static inline bool                 is_base64(unsigned char c) { return (isalnum(c) || (c == '+') || (c == '/')); };
  static const std::string           base64_chars;
  static std::string                 base64_decode(const std::string &encoded_string);
  static std::string                 base64_encode(unsigned char const *bytes_to_encode, unsigned int in_len);
  static void                        closeSocket(ClientSockData *clientSockData);
  std::map<std::string, WebSocket *> webSocketEndPoints;
  static std::string                 SHA1_encode(const std::string &input);
  static const std::string           webSocketMagicString;
  static std::string                 generateWebSocketServerKey(std::string webSocketKey);
  static std::string                 getHttpWebSocketHeader(const char *messageType, const char *webSocketClientKey,
                                                            const bool webSocketDeflate);

public:
  WebServer();

  /**
   * Set the web server name in the http header
   * @param name: the new name
   */
  inline void setWebServerName(const std::string &name) { webServerName = name; }

  /**
   * Set the size of the listener thread pool.
   * @param nbThread: the number of thread available (Default value: 64)
   */
  inline void setThreadsPoolSize(const size_t nbThread) { threadsPoolSize = nbThread; };

  /**
   * Set the tcp port to listen.
   * @param p: the port number, from 1 to 65535 (Default value: 8080)
   */
  inline void setServerPort(const ushort p) { tcpPort = p; };

  /**
   * Set the socket server timeout in seconds
   * @param dur: the socket timeout in seconds. 0 for no timeout, or from 1 to
   * 65535 (Default value: 30)
   */
  inline void setSocketTimeoutInSecond(const ushort dur) { socketTimeoutInSecond = dur; };

  /**
   * Set the device to use (work on linux only).
   * @param d: the device name
   */
  inline void setDevice(const char *d) { device = d; };

  /**
   * Enabled or disabled HTTPS
   * @param ssl: boolean. SSL connections are used if ssl is true.
   * @param certFile: the path to cert file
   * @param certPwd: optional certificat password
   */
  inline void setUseSSL(bool ssl, const char *certFile = "", const char *certPwd = "") {
    mIsSSLEnabled = ssl;
    sslCertFile   = certFile;
    sslCertPwd    = certPwd;
  };

  inline bool isUseSSL() { return mIsSSLEnabled; };

  /**
   * Enabled or disabled X509 authentification
   * @param authPeerSSL: boolean. X509 authentification is required if a is true.
   * @param caFile: the path to cachain file
   */
  inline void setAuthPeerSSL(const bool authPeerSSL = true, const char *caFile = "") {
    mIsAuthPeerSSL = authPeerSSL;
    sslCaFile      = caFile;
  };

  inline bool isAuthPeerSSL() { return mIsAuthPeerSSL; };

  /**
   * Restricted X509 authentification to a DN user list. Add this given DN.
   * @param dn: user certificate DN
   */
  inline void addAuthPeerDN(const char *dn) { authDnList.push_back(std::string(dn)); };

  /**
   * Enabled http authentification for a given login/password list
   * @param login: user login
   * @param pass : user password
   */
  inline void addLoginPass(const char *login, const char *pass) {
    authLoginPwdList.push_back(std::string(login) + ':' + std::string(pass));
  };

  /**
   * Set http Bearer token decode callback function
   * @param realm: realm attribute defining scope of resources being accessed
   * @param decodeCallback: function callback for decoding base64 token and
   * verify signature,
   * tokb64 is the base64 encoded token, secret is the key used for verify token
   * signature, decoded is the token base64
   * decoded
   * without the signature part, returns 0 on success, any other value on fail
   * @param secret: key used for checking token authentication
   * @param expirationCallback: function callback for retriving token expiration
   * date, MUST be provided, returns numbers
   * of
   * seconds since epoch
   * @param scopesCheckCallback: function callback for checking any extra field
   * present in token, optionnal and can be
   * set to NULL,
   * if provided, tokenDecoded is the token base64 decoded as provided by
   * decodeCallback, resourceUrl is the url of the
   * resource being accessed (some scopes may require different value to get
   * access to specific resources), errDescr will
   * be updated with a description of the error to insert in HTTP header error
   * code insufficient_scope, return true on
   * sucess
   */
  inline void setAuthBearerDecodeCallbacks(
      std::string &realm, int (*decodeCallback)(const std::string &tokb64, std::string &secret, std::string &decoded),
      std::string  secret, // GLSR FIXME
      time_t (*expirationCallback)(std::string &tokenDecoded),
      int (*scopesCheckCallback)(const std::string &tokenDecoded, const std::string &resourceUrl,
                                 std::string &errDescr)) {
    authBearerRealm            = realm;
    tokDecodeCallback          = decodeCallback;
    tokDecodeSecret            = secret;
    authBearTokDecExpirationCb = expirationCallback;
    authBearTokDecScopesCb     = scopesCheckCallback;
    authBearerEnabled          = true;
  };

  /**
   * Set the path to store uploaded files on disk. Used to set the MPFD function.
   * @param pathdir: path to a writtable directory
   */
  inline void setMultipartTempDirForFileUpload(const std::string &pathdir) { multipartTempDirForFileUpload = pathdir; };

  /**
   * Set the size of internal MPFD buffer.
   * The buffer is used to store temporary information while parsing field
   * names and other data that identified by any boundaries. In theory some
   * bad man can give you lots of unboundered and eat all your memory. To
   * except this situation you should tell Parser maximum buffer size.
   * Note that file content is transferred directly to disk (of selected)
   * without any buffering.
   * @param max: the internal buffer size
   */
  inline void setMultipartMaxCollectedDataLength(const long &max) { multipartMaxCollectedDataLength = max; };

  /**
   * Add a web repository (containing web pages)
   * @param repo : a pointer to a WebRepository instance
   */
  void addRepository(WebRepository *repo) {
    if (repo != nullptr) {
      webRepositories.push_back(repo);
    } else {
      fatalError("addRepository Failed: try to add a NULL pointer repository");
    }
  };

  /**
   * Add a websocket
   * @param endpoint : websocket endpoint
   * @param websocket : WebSocket instance
   */
  void addWebSocket(const std::string endPoint, WebSocket *websocket) // GLSR FIXME
  {
    if (websocket != nullptr) {
      webSocketEndPoints[endPoint] = websocket;
    } else {
      fatalError("addWebSocket Failed: try to add a NULL pointer websocket");
    }
  };

  /**
   * IpV4 hosts only
   */
  inline void listenIpV4only() { disableIpV6 = true; };

  /**
   * IpV6 hosts only
   */
  inline void listenIpV6only() { disableIpV4 = true; };

  /**
   * set network access restriction to webserver.
   * @param ipnet: an IpNetwork of allowed web client to add
   */
  inline void addHostsAllowed(const IpNetwork &ipnet) { hostsAllowed.push_back(ipnet); };

  /**
   * Get the list of http client peer IP address.
   * @return a map of every IP address and last connection to the webserver
   */
  inline std::map<IpAddress, time_t> &getPeerIpHistory() { return peerIpHistory; };

  /**
   * Get the list of http client DN (work with X509 authentification)
   * @return a map of every DN and last connection to the webserver
   */
  inline std::map<std::string, time_t> &getPeerDnHistory() { return peerDnHistory; };

  /**
   * startService: the webserver starts
   */
  void startService() {
    spdlog::info("WebServer: Service is starting !");
    create_thread(&threadWebServer, WebServer::startThread, this);
  };

  /**
   * stopService: the webserver stops
   */
  void stopService() {
    spdlog::info("WebServer: Service is stopping !");
    exit();
    threadWebServer = 0;
  };

  /**
   * wait until the webserver is stopped
   */
  void wait() { wait_for_thread(threadWebServer); };

  /**
   * is the webserver runnning ?
   */
  bool isRunning() { return threadWebServer != 0; }

  static bool httpSend(ClientSockData *client, const void *buf, size_t len);

  inline static void freeClientSockData(ClientSockData *clientSockData) {
    closeSocket(clientSockData);

    if (clientSockData->ssl) {
      if (clientSockData->peerDN) {
        delete clientSockData->peerDN;
        clientSockData->peerDN = nullptr;
      }
      BIO_free_all(clientSockData->bio);
      /*        SSL_free (clientSockData->ssl);
              if ( clientSockData->bio != NULL )
                BIO_free (clientSockData->bio);*/
      clientSockData->ssl = nullptr;
      clientSockData->bio = nullptr;
    }
    free(clientSockData);
  };
};

#endif
