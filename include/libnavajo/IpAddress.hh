//********************************************************
/**
 * @file  IpAddress.hh
 *
 * @brief Ip Address (V4 and V6) class definition
 *
 * @author T.Descombes (descombes@lpsc.in2p3.fr)
 *
 * @version 1
 * @date 19/02/15
 */
//********************************************************

#ifndef IPADDRESS_HH_
#define IPADDRESS_HH_

#include <cerrno>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef WIN32

#include "pthread.h"
#include <Windows.h>
#include <in6addr.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define u_int32_t uint32_t
#define u_int8_t  uint8_t
#define u_int16_t uint16_t
#include "stdint.h"

#define in_addr_t    DWORD
#define index(s, c)  strchr((char *)s, c)
#define rindex(s, c) strrchr((char *)s, c)

#define inet_ntop(f, b, l, o) inet_ntop(f, (PVOID)(b), l, o)

#else

#include <arpa/inet.h>
#include <netdb.h>

#endif

#include <cstdio>
#include <cstdlib>

#define INET6_ADDRLEN 16

/***********************************************************************
 * IpAdress struct definition
 * for IPv4 and IPv6 address
 */

class IpAddress {
public:
  typedef union {
    in_addr_t v4;
    in6_addr  v6;
  } IP;

  IP       ip;
  u_int8_t ipversion;
  constexpr IpAddress(const IpAddress &) = default;
  virtual ~IpAddress()                   = default;

  void init() {
    ipversion = 0;
    memset(ip.v6.s6_addr, 0, INET6_ADDRLEN);
  }

  IpAddress() { init(); }

  IpAddress(const in_addr_t &addrIPv4) : ipversion(4) { ip.v4 = addrIPv4; }

  IpAddress(const in6_addr &addrIPv6) : ipversion(6) { memcpy((void *)&(ip.v6), (void *)(&addrIPv6), INET6_ADDRLEN); }

  IpAddress(const std::string &value) {
    init();
    if (index(value.c_str(), ':') != nullptr) // IPv6
    {
      struct sockaddr_in6 tmp;
      if (inet_pton(AF_INET6, value.c_str(), &(tmp.sin6_addr)) == 0) {
        return;
      }
      *this = tmp.sin6_addr;
    } else // IPv4
    {
      struct in_addr tmp;
      if (inet_pton(AF_INET, value.c_str(), &tmp) == 0) {
        return;
      }

      *this = tmp.s_addr;
    }
  }

  bool isNull() const { return ipversion == 0; }

  IpAddress &operator=(const in_addr_t &addrIPv4) {
    ipversion = 4;
    ip.v4     = addrIPv4;
    return *this;
  }

  IpAddress &operator=(const in6_addr &addrIPv6) {
    ipversion = 6;
    memcpy((void *)&(ip.v6), (void *)(&addrIPv6), INET6_ADDRLEN);
    return *this;
  }

  IpAddress &operator=(const IpAddress &i) {
    if (i.ipversion == 4) {
      *this = i.ip.v4;
      // ipversion = 4;
      // ip.v4     = addrIPv4;
      return *this;
    } else {
      *this = i.ip.v6;
      // ipversion = 6;
      // memcpy( (void *)&( ip.v6 ), (void *)( &addrIPv6 ), INET6_ADDRLEN );
      return *this;
    }
    return *this;
  }

  bool operator==(IpAddress const &ipA) const {
    if (ipA.ipversion != this->ipversion) {
      return false;
    }

    if (this->ipversion == 4) {
      return this->ip.v4 == ipA.ip.v4;
    }

    if (this->ipversion != 6) {
      return false;
    }

    // IPv6
    int i = INET6_ADDRLEN - 1;
    for (; i >= 0 && (ipA.ip.v6.s6_addr[i] == this->ip.v6.s6_addr[i]); i--) {
      ;
    }
    return i < 0;
  }

  bool operator<(const IpAddress &A) const {
    if (A.ipversion != ipversion) {
      return ipversion < A.ipversion;
    }

    if (ipversion == 4) {
      return ip.v4 < A.ip.v4;
    }

    if (ipversion != 6) {
      return false;
    }

    int i = INET6_ADDRLEN - 1;
    for (; i >= 0 && (ip.v6.s6_addr[i] == A.ip.v6.s6_addr[i]); i--) {
      ;
    }
    if (i < 0) {
      return false; // same Ip address
    } else {
      return ip.v6.s6_addr[i] < A.ip.v6.s6_addr[i];
    }
  }

  bool isUndef() const { return ipversion == 0; }

  std::string str() const {
    std::string res = "";
    if (ipversion == 4) {
      struct in_addr iplocal;
      iplocal.s_addr = ip.v4;
      res += inet_ntoa(iplocal);
    } else { // IPv6
      char ipStr[INET6_ADDRSTRLEN];
      if (inet_ntop(AF_INET6, &(ip.v6), ipStr, INET6_ADDRSTRLEN) == nullptr) {
        res += "ERROR !";
      } else {
        res += ipStr;
      }
    }

    return res;
  }

  static pthread_mutex_t resolvIP_mutex;

  bool snresolve(char *hname, const size_t maxlength) const {
    int                 error = 0;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;

    pthread_mutex_lock(&resolvIP_mutex);

    if (ipversion == 4) {
      sin.sin_family = AF_INET;
      struct in_addr addr;
      addr.s_addr  = ip.v4;
      sin.sin_addr = addr;
      error        = getnameinfo((sockaddr *)&sin, sizeof sin, hname, maxlength, nullptr, 0, NI_NAMEREQD);
    } else { // IPv6
      sin6.sin6_family = AF_INET6;
      sin6.sin6_addr   = ip.v6;
      error            = getnameinfo((sockaddr *)&sin6, sizeof sin6, hname, maxlength, nullptr, 0, NI_NAMEREQD);
    }

    pthread_mutex_unlock(&resolvIP_mutex);

    return (!error);
  }

  static IpAddress *fromHostname(const std::string &hostname, bool preferIpv4 = true) {
    int              status;
    struct addrinfo  hints, *p;
    struct addrinfo *servinfo;
    IpAddress       *newIp4 = nullptr, *newIp6 = nullptr;

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    if ((status = getaddrinfo(hostname.c_str(), nullptr, &hints, &servinfo)) != 0) {
      return nullptr;
    }

    for (p = servinfo; p != nullptr; p = p->ai_next) {
      if (p->ai_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        if (newIp4 == nullptr) {
          newIp4 = new IpAddress((in_addr_t)ipv4->sin_addr.s_addr);
        }
      } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
        if (newIp6 == nullptr) {
          newIp6 = new IpAddress(ipv6->sin6_addr);
        }
      }
    }

    freeaddrinfo(servinfo);

    if (newIp4 != nullptr && !newIp4->isNull() && preferIpv4) {
      if (newIp6 != nullptr) {
        delete newIp6;
      }
      return newIp4;
    }

    if (newIp6 != nullptr && !newIp6->isNull()) {
      if (newIp4 != nullptr) {
        delete newIp4;
      }
      return newIp6;
    }

    if (newIp6 != nullptr) {
      delete newIp6;
    }
    if (newIp4 != nullptr) {
      delete newIp4;
    }

    return nullptr;
  }

  static IpAddress *fromString(const std::string &value) {
    IpAddress *newIp = new IpAddress(value);

    if (newIp != nullptr && !newIp->isNull()) {
      return newIp;
    }

    if (newIp != nullptr) {
      delete newIp;
    }

    return nullptr;
  }
};

/***********************************************************************
 * IpNetwork struct definition
 */

class IpNetwork {
public:
  IpAddress addr;
  u_int8_t  mask;

  IpNetwork() = default;
  IpNetwork(const IpAddress &a) {
    if (a.ipversion == 4) {
      mask = 32;
    } else {
      mask = 128;
    }
    addr = a;
  }

  IpNetwork(const IpAddress &a, const u_int8_t &m) {
    addr = a;
    mask = m;
  }

  // TODO: IpNetwork(const std::string& value)

  bool operator<(const IpNetwork &A) const {
    if (A.addr.ipversion != addr.ipversion) {
      return addr.ipversion < A.addr.ipversion;
    }

    if (A.addr.ipversion == 4) {
      if (addr.ipversion != 4) {
        return false; // IpV6 > IpV4
      }

      u_int32_t netmask = 0, Anetmask = 0;
      for (u_int8_t i = 0; i < A.mask; i++) {
        Anetmask |= 1 << (31 - i);
      }
      Anetmask = htonl(Anetmask);

      for (u_int8_t i = 0; i < mask; i++) {
        netmask |= 1 << (31 - i);
      }
      netmask = htonl(netmask);
      return (addr.ip.v4 & netmask) < (A.addr.ip.v4 & Anetmask);
    }

    if (A.addr.ipversion == 6) {
      if (addr.ipversion != 6) {
        return true; // IpV6 > IpV4
      }

      bool     res     = true;
      int      i       = 0;
      u_int8_t netmask = 0, Anetmask = 0;

      for (; i < INET6_ADDRLEN - 1 && res; i++) {
        for (u_int8_t j = i * 8; j < (i + 1) * 8; j++) {
          if (j < A.mask) {
            Anetmask |= 1 << (8 - (j - i * 8));
          }
          if (j < mask) {
            netmask |= 1 << (8 - (j - i * 8));
          }
        }

        res = (addr.ip.v6.s6_addr[i] & netmask) == (A.addr.ip.v6.s6_addr[i] & Anetmask);
      }
      return res;
    }

    return false;
  }

  std::string strCIDR() const {
    std::string       netCIDR = addr.str() + "/";
    std::stringstream masklengthSs;
    masklengthSs << (int)mask;
    netCIDR += masklengthSs.str();
    return netCIDR;
  }

  /**
   * Is this IP address belonging to this network?
   * @param ip is an ip address
   * @param net is a vector of IpNetwork
   * @return true if it belongs to local network, false otherwise
   */

  bool isInside(const IpAddress &ip) const {
    bool res = false;

    if (ip.ipversion == 4) {
      if (addr.ipversion == 4) {
        u_int32_t netmask = 0;
        for (u_int8_t j = 0; j < mask; j++) {
          netmask |= 1 << (31 - j);
        }
        netmask = htonl(netmask);
        res     = (addr.ip.v4 & netmask) == (ip.ip.v4 & netmask);
      }
    }

    if (ip.ipversion == 6) {
      if (addr.ipversion == 6) {
        res   = true;
        int i = 0;

        for (; i < INET6_ADDRLEN && res; i++) {
          u_int8_t netmask = 0;
          for (u_int8_t j = i * 8; j < (i + 1) * 8; j++) {
            if (j < mask) {
              netmask |= 1 << (8 - (j - i * 8));
            }
          }

          res = ((addr.ip.v6.s6_addr[i] & netmask) == (ip.ip.v6.s6_addr[i] & netmask));
        }
      }
    }

    return res;
  }

  static IpNetwork *fromString(const std::string &value) {
    IpNetwork  *ipNet = nullptr;
    std::string ipstr;
    size_t      found = value.find_first_of('/');
    if (found == std::string::npos) {
      IpAddress *addr = IpAddress::fromString(value);
      if (addr == nullptr) {
        return nullptr;
      }
      ipNet = new IpNetwork(*addr);
      delete addr;
    } else {
      ipstr = value.substr(0, found);

      IpAddress *addr = IpAddress::fromString(ipstr);

      if (addr == nullptr) {
        return nullptr;
      }

      u_int8_t    maskDec = 0;
      std::string maskStr = value.substr(found + 1);

      // Mask
      if (maskStr.find_first_of('.') != std::string::npos) // mask is formating like "w.x.y.z"
      {
        if (addr->ipversion == 6) {
          delete addr;
          return nullptr;
        }

        struct in_addr tmp;
        if (inet_pton(AF_INET, maskStr.c_str(), &tmp) == 0)
        //	if (inet_aton(maskStr.c_str(), &tmp) == 0)
        {
          delete addr;
          return nullptr;
        } else {
          u_int32_t netmask      = ntohl(tmp.s_addr);
          bool      thisistheend = false;
          maskDec                = 0;
          for (u_int8_t j = 0; j < 32; j++) {
            if ((netmask >> (31 - j)) & 1) {
              if (!thisistheend) {
                maskDec++;
              } else {
                delete addr;
                return nullptr;
              }
            } else {
              thisistheend = true;
            }
          }
        }
      } else {
        size_t s = 0, e = 0, j = 0;

        while ((maskStr[s] == ' ' || maskStr[s] == '\t') && s < maskStr.length()) {
          s++;
        }
        e = s;

        if (e < maskStr.length()) {

          while (e < maskStr.length() && maskStr[e] >= '0' && maskStr[e] <= '9') {
            e++;
          }
        }

        j = e;

        while (j < maskStr.length() &&
               (maskStr[j] == ' ' || maskStr[j] == '\t' || maskStr[j] == '\n' || maskStr[j] == '\r')) {
          j++;
        }

        if (e == s || j != maskStr.length()) {
          return nullptr;
        }

        maskDec = atoi(maskStr.substr(s, e - s + 1).c_str());
      }

      if ((maskDec > 32 && addr->ipversion == 4) || (maskDec > 128 && addr->ipversion == 6)) {
        delete addr;
        return nullptr;
      }

      ipNet = new IpNetwork(*addr, maskDec);
      delete addr;
    }
    return ipNet;
  }

  IpNetwork(const std::string &value) {
    IpNetwork *net = fromString(value);
    if (net != nullptr) {
      *this = *net;
      delete net;
    }
  }
};

/**
 * Is this IP address belonging to this list of networks ?
 * @param ip is an ip address
 * @param net is a vector of IpNetwork
 * @return true if it belongs to local network, false otherwise
 */

inline static bool isIpBelongToIpNetwork(const IpAddress &ip, const std::vector<IpNetwork> &net) {
  bool res = false;

  for (std::vector<IpNetwork>::const_iterator i = net.begin(); i != net.end() && !res; ++i) {
    res = i->isInside(ip);
  }

  return res;
}

/***********************************************************************/

#endif
