// ----------------------------------------------------------------------
// Copyright (C) 2021-2021 Geraldo Ribeiro <geraldo@intmain.io>
// ----------------------------------------------------------------------

#include "libnavajo/MemcachedRepository.hh"
#include "libnavajo/GrDebug.hpp"

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
MemcachedRepository::MemcachedRepository(const std::string &prefix, const std::string &server, const int port)
    : mPrefix(prefix), mServer(server), mPort(port) {
  GR_JUMP_TRACE;
  mMemCacheClient = std::make_shared<memcache::Memcache>(mServer, mPort);
}

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
bool MemcachedRepository::getFile(HttpRequest *request, HttpResponse *response) {
  GR_JUMP_TRACE;
  std::string webpage;

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
bool MemcachedRepository::set(const std::string &url, const std::string &value, time_t expiry, uint32_t flags) {
  auto vec = std::vector<char>(value.begin(), value.end());
  return mMemCacheClient->set(mPrefix + url, vec, expiryTime(expiry), flags);
}

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
bool MemcachedRepository::set(const std::string &url, const std::vector<char> &vec, time_t expiry, uint32_t flags) {
  return mMemCacheClient->set(mPrefix + url, vec, expiryTime(expiry), flags);
}

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
bool MemcachedRepository::get(const std::string &url, std::string &value) {
  std::vector<char> vec;
  if (mMemCacheClient->get(mPrefix + url, vec)) {
    value = std::string{vec.begin(), vec.end()};
    return true;
  }
  return false;
}

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
bool MemcachedRepository::get(const std::string &url, std::vector<char> &vec) { return mMemCacheClient->get(mPrefix + url, vec); }

// ----------------------------------------------------------------------
//
// ----------------------------------------------------------------------
bool MemcachedRepository::remove(const std::string &url) { return mMemCacheClient->remove(mPrefix + url); }
