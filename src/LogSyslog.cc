//********************************************************
/**
 * @file  LogSyslog.cc
 *
 * @brief Write log messages to syslog
 *
 * @author T.Descombes (thierry.descombes@gmail.com)
 *
 * @version 1
 * @date 19/02/15
 */
//********************************************************

//#define GR_JUMP_TRACE std::cerr << "\nGRJMP:" << __FILE__ << "/" << __LINE__ << "/" << __PRETTY_FUNCTION__ << std::endl;
#define GR_JUMP_TRACE {}

#include "libnavajo/LogSyslog.hh"

#include <string.h>
#include <syslog.h>

/***********************************************************************/
/**
 * append - append a message
 * \param l - LogSeverity
 * \param m - message
 */
void LogSyslog::append( const NvjLogSeverity &l, const std::string &message, const std::string & /*details*/ )
{
  GR_JUMP_TRACE;

  int type;
  switch( l ) {
  case NVJ_DEBUG:
    type = LOG_DEBUG;
    break;
  case NVJ_WARNING:
    type = LOG_WARNING;
    break;
  case NVJ_ALERT:
    type = LOG_ALERT;
    break;
  case NVJ_ERROR:
    type = LOG_ERR;
    break;
  case NVJ_FATAL:
    type = LOG_EMERG;
    break;
  case NVJ_INFO:
  default:
    type = LOG_INFO;
    break;
  }
  syslog( type, "%s", message.c_str() );
}

/***********************************************************************/
/**
 *  initialize the logoutput
 */

void LogSyslog::initialize()
{
  GR_JUMP_TRACE;
  openlog( ident, LOG_PID, LOG_USER );
  setWithDateTime( false );
}

/***********************************************************************/
/**
 * LogSyslog - constructor
 */

LogSyslog::LogSyslog( const char *id )
{
  GR_JUMP_TRACE;
  strncpy( ident, id, 30 );
}

/***********************************************************************/
/**
 * ~LogRecorder - destructor
 */

LogSyslog::~LogSyslog()
{
  GR_JUMP_TRACE;
  closelog();
}

/***********************************************************************/
