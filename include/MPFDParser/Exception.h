// This file is distributed under GPLv3 licence
// Author: Gorelov Grigory (gorelov@grigory.info)
//
// Contacts and other info are on the WEB page:  grigory.info/MPFDParser

#ifndef _EXCEPTION_H
#define _EXCEPTION_H

#include <cerrno>
#include <iostream>
#include <string>

namespace MPFD {

class Exception {
public:
  Exception(std::string error);
  Exception(const Exception &orig);
  virtual ~Exception();

  std::string GetError() const;

private:
  std::string Error;
};
} // namespace MPFD

#endif /* _EXCEPTION_H */
