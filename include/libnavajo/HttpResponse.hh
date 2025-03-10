//****************************************************************************
/**
 * @file  HttpResponse.hh
 *
 * @brief The Http Response Parameters class
 *
 * @author T.Descombes (descombes@lpsc.in2p3.fr)
 *
 * @version 1
 * @date 27/01/15
 */
//****************************************************************************

#ifndef HTTPRESPONSE_HH_
#define HTTPRESPONSE_HH_

class HttpResponse {
  unsigned char                          *mResponseContent;
  size_t                                  mResponseContentLength;
  std::vector<std::string>                mResponseCookies;
  bool                                    mZippedFile;
  std::string                             mMimeType;
  std::string                             mForwardToUrl;
  bool                                    mCors, mCorsCred;
  std::string                             mCorsDomain;
  unsigned                                mHttpReturnCode;
  std::string                             mHttpReturnCodeMessage;
  std::string                             mHttpSpecificHeaders;
  static const unsigned                   mUnsetHttpReturnCodeMessage = 0;
  static std::map<unsigned, const char *> mHttpReturnCodes;

public:
  HttpResponse(const std::string mime = "")
      : mResponseContent(NULL), mResponseContentLength(0), mZippedFile(false), mMimeType(mime), mForwardToUrl(""),
        mCors(false), mCorsCred(false), mCorsDomain(""), mHttpReturnCode(mUnsetHttpReturnCodeMessage),
        mHttpReturnCodeMessage("Unspecified"), mHttpSpecificHeaders("") {
    initializeHttpReturnCode();
  }

  /************************************************************************/
  /**
   * set the response body
   * @param content: The content's buffer
   * @param length: The content's length
   */
  inline void setContent(unsigned char *const content, const size_t length) {
    mResponseContent       = content;
    mResponseContentLength = length;

    if (mHttpReturnCode == mUnsetHttpReturnCodeMessage) {
      if (length) {
        setHttpReturnCode(200);
      } else {
        setHttpReturnCode(204);
      }
    }
  }

  /************************************************************************/
  /**
   * Returns the response body of the HTTP method
   * @param content: The content's buffer
   * @param length: The content's length
   * @param cookies: The cookies entries
   * @param zip: set to true if the content is compressed (else: false)
   */
  inline void getContent(unsigned char **content, size_t *length, bool *zip) const {
    *content = mResponseContent;
    *length  = mResponseContentLength;
    *zip     = mZippedFile;
  }

  /************************************************************************/
  /**
   * Set if the content is compressed (zip) or not
   * @param b: true if the content is compressed, false if not.
   */
  inline void setIsZipped(bool b = true) { mZippedFile = b; };

  /************************************************************************/
  /**
   * return true if the content is compressed (zip)
   */
  inline bool isZipped() const { return mZippedFile; };

  /************************************************************************/
  /**
   * insert a cookie entry (rfc6265)
   *   format: "<name>=<value>[; <Max-Age>=<age>][; expires=<date>]
   *      [; domain=<domain_name>][; path=<some_path>][; secure][; HttpOnly]"
   * @param name: the cookie's name
   * @param value: the cookie's value
   * @param maxage: the cookie's max-age
   * @param expiresTime: the cookie's expiration date
   * @param path: the cookie's path
   * @param domain: the cookie's domain
   * @param secure: the cookie's secure flag
   * @param httpOnly: the cookie's httpOnly flag
   */

  inline void addCookie(const std::string &name, const std::string &value, const time_t maxage = 0,
                        const time_t expiresTime = 0, const std::string &path = "/", const std::string &domain = "",
                        const bool secure = false, bool httpOnly = false) {
    std::string cookieEntry = name + '=' + value;

    if (maxage) {
      std::stringstream maxageSs;
      maxageSs << maxage;
      cookieEntry += "; Max-Age=" + maxageSs.str();
    }

    if (expiresTime) {
      char      expBuf[100];
      struct tm timeinfo;
      gmtime_r(&expiresTime, &timeinfo);
      strftime(expBuf, 100, "%a, %d %b %Y %H:%M:%S GMT", &timeinfo);
      cookieEntry += "; expires=" + std::string(expBuf);
    }

    if (domain.length())
      cookieEntry += "; domain=" + domain;

    if (path != "/" && path.length())
      cookieEntry += "; path=" + path;

    if (secure)
      cookieEntry += "; secure";

    if (httpOnly)
      cookieEntry += "; HttpOnly";

    mResponseCookies.push_back(cookieEntry);
    spdlog::debug("Adicionado cookie: {}", cookieEntry);
  }

  /************************************************************************/
  /**
   * insert the session's cookie
   * @param sid: the session id
   */
  inline void addSessionCookie(const std::string &sid) {
    addCookie("SID", sid, HttpSession::getSessionLifeTime(), 0, "", "", false, true);
  }

  /************************************************************************/
  /**
   * get the http response's cookies
   * @return the cookies vector
   */
  inline std::vector<std::string> &getCookies() { return mResponseCookies; };

  /************************************************************************/
  /**
   * set a new mime type (by default, mime type is automatically set)
   * @param mime: the new mime type
   */
  inline void setMimeType(const std::string &mime) { mMimeType = mime; }

  /************************************************************************/
  /**
   * get the current mime type
   * @return the mime type
   */
  inline const std::string &getMimeType() const { return mMimeType; }

  /************************************************************************/
  /**
   * Request redirection to a new url
   * @param url: the new url
   */
  void forwardTo(const std::string &url) { mForwardToUrl = url; }

  /************************************************************************/
  /**
   * get the new url
   * @return the new url
   */
  std::string getForwardedUrl() const { return mForwardToUrl; }

  /************************************************************************/
  /**
   * allow Cross Site Request
   * @param cors: enabled or not
   * @param cred: enabled credentials or not
   */
  void setCORS(bool cors = true, bool cred = false, std::string domain = "*") {
    mCors       = cors;
    mCorsCred   = cred;
    mCorsDomain = domain;
  }

  /**
   * is Cross Site Request allowed ?
   * @return boolean
   */
  bool isCORS() { return mCors; }

  bool isCORSwithCredentials() { return mCorsCred; }

  std::string &getCORSdomain() { return mCorsDomain; };

  /************************************************************************/
  /**
   * set Http Return Code
   * @param value: the http return code
   */

  void setHttpReturnCode(const unsigned value) {
    mHttpReturnCode = value;
    std::map<unsigned, const char *>::iterator it;
    it = mHttpReturnCodes.find(value);
    if (it != mHttpReturnCodes.end())
      mHttpReturnCodeMessage = it->second;
    else
      mHttpReturnCodeMessage = "Unspecified";
  }

  /************************************************************************/
  /**
   * set Http Return Code
   * @param value: the http return code
   * @param message: the http return code message
   */
  void setHttpReturnCode(const unsigned value, const std::string message) {
    mHttpReturnCode        = value;
    mHttpReturnCodeMessage = message;
  }

  /************************************************************************/
  /**
   * generate the http return code string
   */
  std::string getHttpReturnCodeStr() {
    if (mHttpReturnCode == mUnsetHttpReturnCodeMessage) {
      setHttpReturnCode(204);
    }

    std::ostringstream httpRetCodeSS; // stream used for the conversion
    httpRetCodeSS << mHttpReturnCode;
    return httpRetCodeSS.str() + " " + mHttpReturnCodeMessage;
  }

  /************************************************************************/
  /**
   * initialize standart Http Return Codes
   * @param value: the http return code
   */
  void initializeHttpReturnCode() const {
    if (mHttpReturnCodes.size()) {
      return;
    }

    // 1xx Informational responses
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(100, "Continue"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(101, "Switching Protocols"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(102, "Processing")); //(WebDAV; RFC 2518)

    // 2xx Success
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(200, "OK"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(201, "Created"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(202, "Accepted"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(203, "Non-Authoritative Information"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(204, "No Content"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(205, "Reset Content"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(206, "Partial Content"));  // (RFC 7233)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(207, "Multi-Status"));     // (WebDAV; RFC 4918)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(208, "Already Reported")); // (WebDAV; RFC 5842)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(226, "IM Used"));          // (RFC 3229)

    // 3xx Redirection
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(300, "Multiple Choices"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(301, "Moved Permanently"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(302, "Found"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(303, "See Other"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(304, "Not Modified")); // (RFC 7232)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(305, "Use Proxy"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(306, "Switch Proxy"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(307, "Temporary Redirect"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(308, "Permanent Redirect")); // (RFC 7538)

    // 4xx Client errors
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(400, "Bad Request"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(401, "Unauthorized")); // (RFC 7235)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(402, "Payment Required"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(403, "Forbidden"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(404, "Not Found"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(405, "Method Not Allowed"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(406, "Not Acceptable"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(407, "Proxy Authentication Required")); // (RFC 7235)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(408, "Request Timeout"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(409, "Conflict"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(410, "Gone"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(411, "Length Required"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(412, "Precondition Failed")); // (RFC 7232)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(413, "Payload Too Large"));   // (RFC 7231)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(414, "URI Too Long"));        //(RFC 7231)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(415, "Unsupported Media Type"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(416, "Range Not Satisfiable")); // (RFC 7233)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(417, "Expectation Failed"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(418, "I'm a teapot"));         // (RFC 2324)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(421, "Misdirected Request"));  // (RFC 7540)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(422, "Unprocessable Entity")); // (WebDAV; RFC 4918)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(423, "Locked"));               // (WebDAV; RFC 4918)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(424, "Failed Dependency"));    // (WebDAV; RFC 4918)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(426, "Upgrade Required"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(428, "Precondition Required"));           // (RFC 6585)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(429, "Too Many Requests"));               //(RFC 6585)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(431, "Request Header Fields Too Large")); // (RFC 6585)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(451, "Unavailable For Legal Reasons"));   // (RFC 7725)

    // 5xx Server error[edit]
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(500, "Internal Server Error"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(501, "Not Implemented"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(502, "Bad Gateway"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(503, "Service Unavailable"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(504, "Gateway Timeout"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(505, "HTTP Version Not Supported"));
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(506, "Variant Also Negotiates")); // (RFC 2295)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(507, "Insufficient Storage"));    // (WebDAV; RFC 4918)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(508, "Loop Detected"));           // (WebDAV; RFC 5842)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(510, "Not Extended"));            // (RFC 2774)
    mHttpReturnCodes.insert(std::pair<unsigned, const char *>(511, "Network Authentication Required")); // (RFC 6585)
  }

  void addSpecificHeader(const char *header) {
    mHttpSpecificHeaders += header;
    mHttpSpecificHeaders += "\r\n";
  }

  void addSpecificHeader(const std::string &header) {
    mHttpSpecificHeaders += header;
    mHttpSpecificHeaders += "\r\n";
  }

  std::string getSpecificHeaders() const { return mHttpSpecificHeaders; }
};

//****************************************************************************

#endif
