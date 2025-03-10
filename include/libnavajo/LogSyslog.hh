//********************************************************
/**
 * @file  LogSyslog.hh
 *
 * @brief write log messages to syslog
 *
 * @author T.Descombes (thierry.descombes@gmail.com)
 *
 * @version 1
 * @date 19/02/15
 */
//********************************************************

#ifndef LOGSYSLOG_HH_
#define LOGSYSLOG_HH_

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "libnavajo/LogOutput.hh"

#define MAX_SYSLOG_ID_SIZE 30

/**
 * LogSyslog - LogOutput
 */
class LogSyslog : public LogOutput {
public:
  LogSyslog(const char *id = "Navajo");
  ~LogSyslog() override;

  void append(const NvjLogSeverity &l, const std::string &m, const std::string &details = "") override;
  void initialize() override;

private:
  char ident[MAX_SYSLOG_ID_SIZE];
};

#endif
