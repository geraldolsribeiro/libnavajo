// This file is distributed under GPLv3 licence
// Author: Gorelov Grigory (gorelov@grigory.info)
//
// Contacts and other info are on the WEB page:  grigory.info/MPFDParser

// ---- ORIGINAL -----

#include "libnavajo/GrDebug.hpp"
#include <spdlog/spdlog.h>

#include "MPFDParser/Parser.h"

std::map<std::string, MPFD::Field *> MPFD::Parser::GetFieldsMap() {
  GR_JUMP_TRACE;
  return Fields;
}

MPFD::Field *MPFD::Parser::GetField(std::string Name) {
  GR_JUMP_TRACE;
  if (Fields.count(Name)) {
    return Fields[Name];
  } else {
    return nullptr;
  }
}

MPFD::Parser::Parser() {
  GR_JUMP_TRACE;
  DataCollector                  = nullptr;
  DataCollectorLength            = 0;
  _HeadersOfTheFieldAreProcessed = false;
  CurrentStatus                  = Status_LookingForStartingBoundary;

  MaxDataCollectorLength = 16 * 1024 * 1024; // 16 Mb default data collector size.

  SetUploadedFilesStorage(StoreUploadedFilesInFilesystem);
}

MPFD::Parser::~Parser() {
  GR_JUMP_TRACE;
  std::map<std::string, Field *>::iterator it;
  for (it = Fields.begin(); it != Fields.end(); ++it) {
    delete it->second;
  }

  // GLSR
  if (DataCollector) {
    delete DataCollector;
  }
}

void MPFD::Parser::SetContentType(const std::string type) {
  GR_JUMP_TRACE;
  if (type.find("multipart/form-data;") != 0) {
    throw MPFD::Exception(std::string("Content type is not \"multipart/form-data\"\nIt is \"") + type +
                          std::string("\""));
  }

  std::size_t bp = type.find("boundary=");

  if (bp == std::string::npos) {
    throw MPFD::Exception(std::string("Cannot find boundary in Content-type: \"") + type + std::string("\""));
  }

  // GLSR
  Boundary = std::string("--") + type.substr(bp + 9);
}

void MPFD::Parser::AcceptSomeData(const char *data, const long length) {
  GR_JUMP_TRACE;
  if (Boundary.length() > 0) {
    // Append data to existing accumulator
    if (DataCollector == nullptr) {
      DataCollector = new char[length];
      memcpy(DataCollector, data, length);
      DataCollectorLength = length;
    } else {
      DataCollector = (char *)realloc(DataCollector, DataCollectorLength + length);
      memcpy(DataCollector + DataCollectorLength, data, length);
      DataCollectorLength += length;
    }

    if (DataCollectorLength > MaxDataCollectorLength) {
      throw Exception("Maximum data collector length reached.");
    }

    _ProcessData();
  } else {
    throw MPFD::Exception("Accepting data, but content type was not set.");
  }
}

void MPFD::Parser::_ProcessData() {
  GR_JUMP_TRACE;
  // If some data left after truncate, process it right now.
  // Do not wait for AcceptSomeData called again
  bool NeedToRepeat;

  do {
    NeedToRepeat = false;
    switch (CurrentStatus) {
    case Status_LookingForStartingBoundary:
      if (FindStartingBoundaryAndTruncData()) {
        CurrentStatus = Status_ProcessingHeaders;
        NeedToRepeat  = true;
      }
      break;

    case Status_ProcessingHeaders:
      if (WaitForHeadersEndAndParseThem()) {
        CurrentStatus = Status_ProcessingContentOfTheField;
        NeedToRepeat  = true;
      }
      break;

    case Status_ProcessingContentOfTheField:
      if (ProcessContentOfTheField()) {
        CurrentStatus = Status_LookingForStartingBoundary;
        NeedToRepeat  = true;
      }
      break;
    }
  } while (NeedToRepeat);
}

bool MPFD::Parser::ProcessContentOfTheField() {
  GR_JUMP_TRACE;
  long BoundaryPosition = BoundaryPositionInDataCollector();
  long DataLengthToSendToField;
  if (BoundaryPosition >= 0) {
    // 2 is the \r\n before boundary we do not need them
    DataLengthToSendToField = BoundaryPosition - 2;
  } else {
    // We need to save +2 chars for \r\n chars before boundary
    DataLengthToSendToField = DataCollectorLength - (Boundary.length() + 2);
  }

  if (DataLengthToSendToField > 0) {
    Fields[ProcessingFieldName]->AcceptSomeData(DataCollector, DataLengthToSendToField);
    TruncateDataCollectorFromTheBeginning(DataLengthToSendToField);

    // GLSR Campos duplicados
    auto processingFieldNameArr = ProcessingFieldName + "[]";
    if (Fields.count(processingFieldNameArr)) {
      Fields[processingFieldNameArr]->SetType(Field::TextType);
      auto currentFieldContent = Fields[processingFieldNameArr]->GetTextTypeContent();
      if (!currentFieldContent.empty()) {
        currentFieldContent = "|";
      }
      currentFieldContent += Fields[ProcessingFieldName]->GetTextTypeContent();
      Fields[processingFieldNameArr]->AcceptSomeData(const_cast<char *>(currentFieldContent.c_str()),
                                                     currentFieldContent.size());
      // spdlog::debug( "ProcessContentOfTheField {} -> {}", ProcessingFieldName, currentFieldContent );
    }
  }

  if (BoundaryPosition >= 0) {
    CurrentStatus = Status_LookingForStartingBoundary;
    return true;
  } else {
    return false;
  }
}

bool MPFD::Parser::WaitForHeadersEndAndParseThem() {
  GR_JUMP_TRACE;

  for (int i = 0; i < DataCollectorLength - 3; i++) {
    if ((DataCollector[i] == 13) && (DataCollector[i + 1] == 10) && (DataCollector[i + 2] == 13) &&
        (DataCollector[i + 3] == 10)) {
      long  headers_length = i;
      char *headers        = new char[headers_length + 1];
      memset(headers, 0, headers_length + 1);
      memcpy(headers, DataCollector, headers_length);

      _ParseHeaders(std::string(headers));

      TruncateDataCollectorFromTheBeginning(i + 4);

      delete[] headers;

      return true;
    }
  }
  return false;
}

void MPFD::Parser::SetUploadedFilesStorage(int where) {
  GR_JUMP_TRACE;
  spdlog::debug("MPFD::Parser::SetUploadedFilesStorage where: {}", where);
  WhereToStoreUploadedFiles = where;
}

void MPFD::Parser::SetTempDirForFileUpload(std::string dir) {
  GR_JUMP_TRACE;
  spdlog::debug("MPFD::Parser::SetTempDirForFileUpload dir: {}", dir);
  TempDirForFileUpload = dir;
}

void MPFD::Parser::_ParseHeaders(std::string headers) {
  GR_JUMP_TRACE;
  spdlog::debug("MPDF::Parser::_ParseHeaders headers: {}", headers);
  // Check if it is form data
  if (headers.find("Content-Disposition: form-data;") == std::string::npos) {
    throw Exception(std::string("Accepted headers of field does not contain "
                                "\"Content-Disposition: form-data;\"\nThe "
                                "headers are: \"") +
                    headers + std::string("\""));
  }

  // Find name
  std::size_t name_pos = headers.find("name=\"");
  if (name_pos == std::string::npos) {
    throw Exception(std::string("Accepted headers of field does not contain "
                                "\"name=\".\nThe headers are: \"") +
                    headers + std::string("\""));
  } else {
    std::size_t name_end_pos = headers.find("\"", name_pos + 6);
    if (name_end_pos == std::string::npos) {
      throw Exception(std::string("Cannot find closing quote of \"name=\" "
                                  "attribute.\nThe headers are: \"") +
                      headers + std::string("\""));
    } else {
      ProcessingFieldName = headers.substr(name_pos + 6, name_end_pos - (name_pos + 6));
      // GLSR Campos duplicados
      if (Fields.count(ProcessingFieldName) and Fields.count(ProcessingFieldName + "[]")) {
        Fields[ProcessingFieldName + "[]"] = new Field();
        // spdlog::debug( "_ParseHeaders {}", ProcessingFieldName );
      }
      Fields[ProcessingFieldName] = new Field();
    }

    // find filename if exists
    std::size_t filename_pos = headers.find("filename=\"");
    if (filename_pos == std::string::npos) {
      Fields[ProcessingFieldName]->SetType(Field::TextType);
    } else {
      Fields[ProcessingFieldName]->SetType(Field::FileType);
      Fields[ProcessingFieldName]->SetTempDir(TempDirForFileUpload);
      Fields[ProcessingFieldName]->SetUploadedFilesStorage(WhereToStoreUploadedFiles);

      std::size_t filename_end_pos = headers.find("\"", filename_pos + 10);
      if (filename_end_pos == std::string::npos) {
        throw Exception(std::string("Cannot find closing quote of \"filename=\" "
                                    "attribute.\nThe headers are: \"") +
                        headers + std::string("\""));
      } else {
        std::string filename = headers.substr(filename_pos + 10, filename_end_pos - (filename_pos + 10));
        Fields[ProcessingFieldName]->SetFileName(filename);
      }

      // find Content-Type if exists
      std::size_t content_type_pos = headers.find("Content-Type: ");
      if (content_type_pos != std::string::npos) {
        std::size_t content_type_end_pos = 0;
        for (std::size_t i = content_type_pos + 14; (i < headers.length()) && (!content_type_end_pos); i++) {
          if ((headers[i] == ' ') || (headers[i] == 10) || (headers[i] == 13)) {
            content_type_end_pos = i - 1;
          }
        }
        std::string content_type =
            headers.substr(content_type_pos + 14, content_type_end_pos - (content_type_pos + 14));
        Fields[ProcessingFieldName]->SetFileContentType(content_type);
      }
    }
  }
}

void MPFD::Parser::SetMaxCollectedDataLength(long max) {
  GR_JUMP_TRACE;
  spdlog::debug("MPFD::Parser::SetMaxCollectedDataLength max: {}", max);
  MaxDataCollectorLength = max;
}

void MPFD::Parser::TruncateDataCollectorFromTheBeginning(long n) {
  GR_JUMP_TRACE;
  spdlog::debug("MPFD::Parser::TruncateDataCollectorFromTheBeginning n: {}", n);
  long TruncatedDataCollectorLength = DataCollectorLength - n;

  char *tmp = DataCollector;

  DataCollector = new char[TruncatedDataCollectorLength];
  memcpy(DataCollector, tmp + n, TruncatedDataCollectorLength);

  DataCollectorLength = TruncatedDataCollectorLength;

  delete tmp;
}

long MPFD::Parser::BoundaryPositionInDataCollector() {
  GR_JUMP_TRACE;
  const char *b  = Boundary.c_str();
  int         bl = Boundary.length();
  if (DataCollectorLength >= bl) {
    bool found = false;
    for (int i = 0; (i <= DataCollectorLength - bl) && (!found); i++) {
      found = true;
      for (int j = 0; (j < bl) && (found); j++) {
        if (DataCollector[i + j] != b[j]) {
          found = false;
        }
      }

      if (found) {
        return i;
      }
    }
  }
  return -1;
}

bool MPFD::Parser::FindStartingBoundaryAndTruncData() {
  GR_JUMP_TRACE;
  long n = BoundaryPositionInDataCollector();
  if (n >= 0) {
    TruncateDataCollectorFromTheBeginning(n + Boundary.length());
    return true;
  } else {
    return false;
  }
}
