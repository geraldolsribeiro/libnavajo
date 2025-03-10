// ----------------------------------------------------------------------
// Copyright (C) 2021-2021 Geraldo Ribeiro <geraldo@intmain.io>
// ----------------------------------------------------------------------

#include "libnavajo/MemcachedRepository.hh"
#include "libnavajo/GrDebug.hpp"

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
MemcachedRepository::MemcachedRepository(const string &prefix, const string &server, const int port)
    : mPrefix(prefix), mServer(server), mPort(port) {
  GR_JUMP_TRACE;
  mMemCacheClient = make_shared<memcache::Memcache>(mServer, mPort);
}

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
bool MemcachedRepository::getFile(HttpRequest *request, HttpResponse *response) {
  GR_JUMP_TRACE;
  string webpage;

  if (!get(request->getUrl(), webpage)) {
    return false;
  }

  unsigned char *buffer = new unsigned char[webpage.size() + 1];
  copy(webpage.begin(), webpage.end(), buffer);
  response->setContent(buffer, webpage.size());
  return true;
}

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
void MemcachedRepository::freeFile(unsigned char *webpage) {
  GR_JUMP_TRACE;
  ::free(webpage);
}

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
time_t MemcachedRepository::expiryTime(const time_t t) {
  if (t == 0) {
    return time(nullptr) + 600; // retem na memória por 10 minutos
  }
  return t;
}

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
bool MemcachedRepository::set(const string &url, const string &value, time_t expiry, uint32_t flags) {
  auto vec = vector<char>(value.begin(), value.end());
  return mMemCacheClient->set(mPrefix + url, vec, expiryTime(expiry), flags);
}

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
bool MemcachedRepository::set(const string &url, const vector<char> &vec, time_t expiry, uint32_t flags) {
  return mMemCacheClient->set(mPrefix + url, vec, expiryTime(expiry), flags);
}

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
bool MemcachedRepository::get(const string &url, string &value) {
  vector<char> vec;
  if (mMemCacheClient->get(mPrefix + url, vec)) {
    value = string{vec.begin(), vec.end()};
    return true;
  }
  return false;
}

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
bool MemcachedRepository::get(const string &url, vector<char> &vec) { return mMemCacheClient->get(mPrefix + url, vec); }

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
bool MemcachedRepository::remove(const string &url) { return mMemCacheClient->remove(mPrefix + url); }
