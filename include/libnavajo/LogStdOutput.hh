//********************************************************
/**
 * @file  LogStdOutput.hh
 *
 * @brief write log messages to standart output
 *
 * @author T.Descombes (thierry.descombes@gmail.com)
 *
 * @version 1
 * @date 19/02/15
 */
//********************************************************

#ifndef LOGSTDOUTPUT_HH_
#define LOGSTDOUTPUT_HH_

#include "libnavajo/LogOutput.hh"

/**
 * LogStdOutput - LogOutput
 */
class LogStdOutput : public LogOutput {
public:
  LogStdOutput();
  ~LogStdOutput() override;

  void append(const NvjLogSeverity &l, const std::string &m, const std::string &details = "") override;
  void initialize() override;
};

#endif
