// This file is distributed under GPLv3 licence
// Author: Gorelov Grigory (gorelov@grigory.info)
//
// Contacts and other info are on the WEB page:  grigory.info/MPFDParser

//#define GR_JUMP_TRACE std::cerr << "\nGRJMP:" << __FILE__ << "/" << __LINE__ << "/" << __PRETTY_FUNCTION__ <<
//std::endl;
#define GR_JUMP_TRACE                                                                                                  \
  {                                                                                                                    \
  }

#include "MPFDParser/Exception.h"

MPFD::Exception::Exception( std::string error )
{
  GR_JUMP_TRACE;
  Error = error;
}

MPFD::Exception::Exception( const MPFD::Exception &orig )
{
  GR_JUMP_TRACE;
  Error = orig.Error;
}

MPFD::Exception::~Exception()
{
  GR_JUMP_TRACE;
}

std::string MPFD::Exception::GetError() const
{
  GR_JUMP_TRACE;
  return Error;
}
