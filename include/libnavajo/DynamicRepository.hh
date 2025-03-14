//********************************************************
/**
 * @file  DynamicRepository.hh
 *
 * @brief Handles dynamic web repository
 *
 * @author T.Descombes (descombes@lpsc.in2p3.fr)
 *
 * @version 1
 * @date 19/02/15
 */
//********************************************************

#ifndef DYNAMICREPOSITORY_HH_
#define DYNAMICREPOSITORY_HH_

#include "libnavajo/GrDebug.hpp"

#include <map>
#include <string>

#include "libnavajo/WebRepository.hh"

class DynamicRepository : public WebRepository {

  pthread_mutex_t                              _mutex;
  typedef std::map<std::string, DynamicPage *> IndexMap;
  IndexMap                                     indexMap;

public:
  DynamicRepository() {
    GR_JUMP_TRACE;
    pthread_mutex_init(&_mutex, nullptr);
  }
  virtual ~DynamicRepository() {
    GR_JUMP_TRACE;
    indexMap.clear();
  }

  /**
   * Free resources after use. Inherited from class WebRepository
   * called from WebServer::accept_request() method
   * @param webpage: a pointer to the generated page
   */
  inline void freeFile(unsigned char *webpage) override {
    GR_JUMP_TRACE;
    ::free(webpage);
  }

  /**
   * Add new page to the repository
   * @param name: the url (from the document root)
   * @param page: the DynamicPage instance responsible for content generation
   */
  // GLSR FIXME
  inline void add(const std::string url, DynamicPage *page) {
    GR_JUMP_TRACE;
    size_t i = 0;
    while (url.size() && url[i] == '/') {
      GR_JUMP_TRACE;
      i++;
    }
    pthread_mutex_lock(&_mutex);
    indexMap.insert(std::pair<std::string, DynamicPage *>(url.substr(i, url.size() - i), page));
    pthread_mutex_unlock(&_mutex);
  }

  /**
   * Remove page from the repository
   * @param urlToRemove: the url (from the document root)
   * @param deleteDynamicPage: true if the related DynamicPage must be deleted
   */
  // GLSR FIXME
  inline void remove(const std::string urlToRemove, bool deleteDynamicPage = false) {
    GR_JUMP_TRACE;
    std::string url(urlToRemove);
    while (url.size() && url[0] == '/') {
      GR_JUMP_TRACE;
      url.erase(0, 1);
    }
    pthread_mutex_lock(&_mutex);
    IndexMap::iterator i = indexMap.find(url);
    if (i == indexMap.end()) {
      GR_JUMP_TRACE;
      pthread_mutex_unlock(&_mutex);
      return;
    } else {
      GR_JUMP_TRACE;
      pthread_mutex_unlock(&_mutex);
      if (deleteDynamicPage) {
        GR_JUMP_TRACE;
        delete i->second;
      }
      indexMap.erase(i);
      return;
    }

    pthread_mutex_lock(&_mutex);
  }

  /**
   * Try to resolve an http request by requesting the DynamicRepository.
   * Inherited from class WebRepository
   * called from WebServer::accept_request() method
   * @param request: a pointer to the current request
   * @param response: a pointer to the new generated response
   * \return true if the repository contains the requested resource
   */
  inline bool getFile(HttpRequest *request, HttpResponse *response) override {
    GR_JUMP_TRACE;
    std::string url = request->getUrl();
    while (url.size() && url[0] == '/') {
      url.erase(0, 1);
    }
    pthread_mutex_lock(&_mutex);
    IndexMap::const_iterator i = indexMap.find(url);
    if (i == indexMap.end()) {
      GR_JUMP_TRACE;
      pthread_mutex_unlock(&_mutex);
      return false;
    } else {
      GR_JUMP_TRACE;
      pthread_mutex_unlock(&_mutex);
      bool res = i->second->getPage(request, response);
      if (request->getSessionId().size()) {
        response->addSessionCookie(request->getSessionId());
      }
      return res;
    }
  }
};
#endif
