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

#include <cstdlib>
#include <cstring>

#include "libnavajo/GrDebug.hpp"
#include "libnavajo/LogFile.hh"

/***********************************************************************/
/**
 * add - add an entry to the LogRecorder
 * \param l - type of entry
 * \param m - message
 */
void LogFile::append(const NvjLogSeverity & /*l*/, const std::string &message, const std::string & /*details*/) {
  GR_JUMP_TRACE;
  if (file != nullptr) {
    (*file) << message << std::endl;
  }
}

/***********************************************************************/
/**
 * LogFile - initialize
 */

void LogFile::initialize() {
  GR_JUMP_TRACE;
  file = new std::ofstream;
  file->open(filename, std::ios::out | std::ios::app);

  if (file->fail()) {
    std::cerr << "Can't open " << filename << std::endl;
    exit(1);
  }
}

/***********************************************************************/
/**
 * LogFile - constructor
 */

LogFile::LogFile(const char *f) {
  GR_JUMP_TRACE;
  strncpy(filename, f, 30);
  file = nullptr;
  // setWithEndline(true);
}

/***********************************************************************/
/**
 * ~LogRecorder - destructor
 */

LogFile::~LogFile() {
  GR_JUMP_TRACE;
  if (file != nullptr) {
    file->close();
    delete file;
  }
}

/***********************************************************************/
