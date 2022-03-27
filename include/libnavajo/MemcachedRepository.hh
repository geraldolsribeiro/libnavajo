#ifndef __MEMCACHED_REPOSITORY_HH__
#define __MEMCACHED_REPOSITORY_HH__

#include <libmemcached/memcached.hpp>
#include <memory>
#include <string>
#include <vector>

using namespace std;

#include "WebRepository.hh"
#include "libnavajo/GrDebug.hpp"

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
class MemcachedRepository : public WebRepository {
private:
  shared_ptr<memcache::Memcache> mMemCacheClient;
  string                         mPrefix;
  string                         mServer;
  int                            mPort;
  time_t                         expiryTime( const time_t t );
  bool                           get( const string &url, vector<char> &vec );
  bool                           get( const string &url, string &value );

public:
  MemcachedRepository( const string &prefix, const string &server = "127.0.0.1", const int port = 11211 );
  virtual ~MemcachedRepository(){};
  bool set( const string &url, const vector<char> &vec, time_t expiry = 0, uint32_t flags = 0 );
  bool set( const string &url, const string &value, time_t expiry = 0, uint32_t flags = 0 );
  bool remove( const string &url );
  bool getFile( HttpRequest *request, HttpResponse *response ) override;
  void freeFile( unsigned char *webpage ) override;
};

#endif
