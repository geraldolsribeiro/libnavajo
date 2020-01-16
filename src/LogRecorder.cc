//********************************************************
/**
 * @file  LogRecorder.cc
 *
 * @brief Log Manager class
 *
 * @author T.Descombes (thierry.descombes@gmail.com)
 *
 * @version 1
 * @date 19/02/15
 */
//********************************************************

//#define GR_JUMP_TRACE std::cerr << "\nGRJMP:" << __FILE__ << "/" << __LINE__ << "/" << __PRETTY_FUNCTION__ << std::endl;
#define GR_JUMP_TRACE;

#include <iostream>

#include "libnavajo/LogRecorder.hh"
#include <time.h>

/**
 * LogRecorder - static and unique log recorder object
 */
LogRecorder *LogRecorder::theLogRecorder = NULL;

/***********************************************************************/
/**
 * getDateStr - return a string with the formatted date
 * \return string - formatted date
 */
std::string LogRecorder::getDateStr()
{
  GR_JUMP_TRACE;
  struct tm today;
  char      tmpbuf[128];
  time_t    ltime;

  time( &ltime );
  gmtime_r( &ltime, &today );

  std::string ret_str;
  strftime( tmpbuf, 128, "[%Y-%m-%d %H:%M:%S] >  ", &today );
  ret_str = tmpbuf;
  return ret_str;
}

/***********************************************************************/
/**
 * append - append an entry to the LogRecorder
 * \param l - type of entry
 * \param m - message
 */
void LogRecorder::append( const NvjLogSeverity &l, const std::string &m, const std::string &details )
{
  GR_JUMP_TRACE;
  pthread_mutex_lock( &log_mutex );

  if( l != NVJ_DEBUG || debugMode ) {
    for( std::list<LogOutput *>::iterator it = logOutputsList_.begin(); it != logOutputsList_.end(); ++it ) {
      std::string msg;

      if( ( *it )->isWithDateTime() )
        msg = getDateStr() + m;
      else
        msg = m;

      if( ( *it )->isWithEndline() )
        msg += std::string( "\n" );

      ( *it )->append( l, msg, details );
    }
  }

  pthread_mutex_unlock( &log_mutex );
}

/***********************************************************************/
/**
 * addLogOutput - ajout d'une sortie LogOutput où imprimer les logs
 */

void LogRecorder::addLogOutput( LogOutput *output )
{
  GR_JUMP_TRACE;
  output->initialize();
  logOutputsList_.push_back( output );
}

/***********************************************************************/
/**
 * removeLogOutputs - supprime toutes les sorties LogOutput
 */
void LogRecorder::removeLogOutputs()
{
  GR_JUMP_TRACE;
  for( std::list<LogOutput *>::iterator it = logOutputsList_.begin(); it != logOutputsList_.end(); ++it )
    delete *it;

  logOutputsList_.clear();
}

/***********************************************************************/
/**
 * LogRecorder - base constructor
 */

LogRecorder::LogRecorder()
{
  GR_JUMP_TRACE;
  debugMode = false;
  pthread_mutex_init( &log_mutex, NULL );
}

/***********************************************************************/
/**
 * ~LogRecorder - destructor
 */
LogRecorder::~LogRecorder()
{
  GR_JUMP_TRACE;
  removeLogOutputs();
}

/***********************************************************************/
