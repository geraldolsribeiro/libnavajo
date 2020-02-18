//*******************************************************
/**
 * @file  LogFile.cc
 *
 * @brief Write log messages to a file
 *
 * @author T.Descombes (thierry.descombes@gmail.com)
 *
 * @version 1
 * @date 19/02/15
 */
//********************************************************

//#define GR_JUMP_TRACE std::cerr << "\nGRJMP:" << __FILE__ << "/" << __LINE__ << "/" << __PRETTY_FUNCTION__ <<
// std::endl;
#define GR_JUMP_TRACE                                                                                                  \
  {                                                                                                                    \
  }

#include <stdlib.h>
#include <string.h>

#include "libnavajo/LogFile.hh"

/***********************************************************************/
/**
 * add - add an entry to the LogRecorder
 * \param l - type of entry
 * \param m - message
 */
void LogFile::append( const NvjLogSeverity & /*l*/, const std::string &message, const std::string & /*details*/ )
{
  GR_JUMP_TRACE;
  if( file != NULL ) {
    ( *file ) << message << std::endl;
  }
}

/***********************************************************************/
/**
 * LogFile - initialize
 */

void LogFile::initialize()
{
  GR_JUMP_TRACE;
  file = new std::ofstream;
  file->open( filename, std::ios::out | std::ios::app );

  if( file->fail() ) {
    std::cerr << "Can't open " << filename << std::endl;
    exit( 1 );
  }
}

/***********************************************************************/
/**
 * LogFile - constructor
 */

LogFile::LogFile( const char *f )
{
  GR_JUMP_TRACE;
  strncpy( filename, f, 30 );
  file = NULL;
  // setWithEndline(true);
}

/***********************************************************************/
/**
 * ~LogRecorder - destructor
 */

LogFile::~LogFile()
{
  GR_JUMP_TRACE;
  if( file != NULL ) {
    file->close();
    delete file;
  }
}

/***********************************************************************/
