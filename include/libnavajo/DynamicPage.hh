//********************************************************
/**
 * @file  DynamicPage.hh
 *
 * @brief Dynamic page définition (abstract class)
 *
 * @author T.Descombes (descombes@lpsc.in2p3.fr)
 *
 * @version 1
 * @date 19/02/15
 */
//********************************************************

#ifndef DYNAMICPAGE_HH_
#define DYNAMICPAGE_HH_

#include <algorithm>
#include <cctype>
#include <string>
#include <typeinfo>

#include <libnavajo/HttpRequest.hh>
#include <libnavajo/HttpResponse.hh>

class DynamicPage {

public:
  DynamicPage() {};
  virtual ~DynamicPage() {};

  virtual bool getPage(HttpRequest *request, HttpResponse *response) = 0;

  /**********************************************************************/

  template <class T> static inline T getValue(const std::string &s) {
    if (!s.length()) {
      throw std::bad_cast();
    }

    std::istringstream iss(s);
    T                  tmp;
    iss >> tmp;

    if (iss.fail()) {
      throw std::bad_cast();
    }

    return tmp;
  }

  /**********************************************************************/

  static inline bool isNotPrintable(char c) { return !isprint(static_cast<unsigned char>(c)); }

  static inline void stripUnprintableChar(std::string &str) {
    str.erase(std::remove_if(str.begin(), str.end(), isNotPrintable), str.end());
  }

  /**********************************************************************/

  inline bool noContent(HttpResponse *response) {
    response->setContent(nullptr, 0);
    return true;
  }

  /**********************************************************************/

  inline bool fromString(const std::string &resultat, HttpResponse *response) const {
    size_t         webpageLen;
    unsigned char *webpage;
    if ((webpage = (unsigned char *)malloc(resultat.size() + 1 * sizeof(char))) == nullptr) {
      return false;
    }
    webpageLen = resultat.size();
    strcpy((char *)webpage, resultat.c_str());
    response->setContent(webpage, webpageLen);
    return true;
  }
};

#endif
