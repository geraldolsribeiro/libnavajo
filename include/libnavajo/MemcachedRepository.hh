#ifndef __MEMCACHED_REPOSITORY_HH__
#define __MEMCACHED_REPOSITORY_HH__

#include <cinttypes>
#include <memory>
#include <string>
#include <vector>


#include <libmemcached/memcached.hpp>

#include "WebRepository.hh"
#include "libnavajo/GrDebug.hpp"

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
class MemcachedRepository : public WebRepository {
private:
  std::shared_ptr<memcache::Memcache> mMemCacheClient;
  std::string mPrefix;
  std::string mServer;
  int mPort;
  time_t expiryTime(const time_t t);
  bool get(const std::string &url, std::vector<char> &vec);
  bool get(const std::string &url, std::string &value);

public:
  MemcachedRepository(const std::string &prefix, const std::string &server = "127.0.0.1",
                      const int port = 11211);
  virtual ~MemcachedRepository() {};
  bool set(const std::string &url, const std::vector<char> &vec, time_t expiry = 0,
           uint32_t flags = 0);
  bool set(const std::string &url, const std::string &value, time_t expiry = 0,
           uint32_t flags = 0);
  bool remove(const std::string &url);
  bool getFile(HttpRequest *request, HttpResponse *response) override;
  void freeFile(unsigned char *webpage) override;
};

#endif
