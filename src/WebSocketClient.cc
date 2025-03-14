//********************************************************
/**
 * @file  WebSocketClient.cc
 *
 * @brief The WebSocket client class
 *        rfc6455 The WebSocket Protocol
 *
 * @author T.Descombes (thierry.descombes@gmail.com)
 *
 * @version 1
 * @date 19/02/16
 */
//********************************************************

#include "libnavajo/GrDebug.hpp"
#include "libnavajo/WebServer.hh"
#include "libnavajo/WebSocket.hh"
#include "libnavajo/htonll.h"
#include "libnavajo/nvjSocket.h"

#define BUFSIZE 32768

/***********************************************************************/

WebSocketClient::WebSocketClient(WebSocket *ws, HttpRequest *req) : mWebsocket(ws), mRequest(req), mClosing(false) {
  GR_JUMP_TRACE;
  snd_maxLatency = ws->getClientSendingMaxLatency();
  pthread_mutex_init(&sendingQueueMutex, nullptr);
  pthread_cond_init(&sendingNotification, nullptr);
  gzipcontext.dictInfLength = 0;
  nvj_init_stream(&(gzipcontext.strm_deflate), true);
  noSessionExpiration(mRequest);
  startWebSocketThreads();
}

/***********************************************************************/

void WebSocketClient::sendingThread() {
  GR_JUMP_TRACE;
  pthread_mutex_lock(&sendingQueueMutex);

  for (;;) {
    while (sendingQueue.empty() && !mClosing) {
      pthread_cond_wait(&sendingNotification, &sendingQueueMutex);
    }

    if (mClosing) {
      break;
    }

    MessageContent *msg = sendingQueue.front();
    sendingQueue.pop();
    pthread_mutex_unlock(&sendingQueueMutex);

    long long msgLatency = (unsigned long long)(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                    std::chrono::steady_clock::now().time_since_epoch())
                                                    .count() -
                                                msg->date_ms);

    if (msgLatency > snd_maxLatency || !sendMessage(msg)) {
      free(msg->message);
      free(msg);
      closeSend();
      return;
    }
    free(msg->message);
    free(msg);
    pthread_mutex_lock(&sendingQueueMutex);
  }

  freeSendingQueue();

  pthread_mutex_unlock(&sendingQueueMutex);
}

/***********************************************************************/

void WebSocketClient::receivingThread() {
  GR_JUMP_TRACE;
  char      bufferRecv[BUFSIZE];
  u_int64_t msgLength = 0, msgContentIt = 0;
  bool      msgMask = false;

  unsigned char  msgKeys[4];
  unsigned char *msgContent = nullptr;
  enum MsgDecodSteps { FIRSTBYTE, LENGTH, MASK, CONTENT };

  ClientSockData *client = mRequest->getClientSockData();

  if (mWebsocket->getWebsocketTimeoutInMilliSecond() &&
      !setSocketSndRcvTimeout(client->socketId, 0,
                              mWebsocket->getWebsocketTimeoutInMilliSecond())) { // Reduce socket timeout
    spdlog::error("WebSocketClient : setSocketSndRcvTimeout error");
    closeRecv();
    return;
  }

  if (!mWebsocket->isUsingNaggleAlgo()) {
    if (!setSocketNagleAlgo(client->socketId, false)) // Disable Naggle Algorithm
    {
      spdlog::error("WebSocketClient : setSocketNagleAlgo error");
      closeRecv();
      return;
    }
  }

  bool          fin = false;
  unsigned char rsv = 0, opcode = 0;
  u_int64_t     readLength = 1;
  MsgDecodSteps step       = FIRSTBYTE;
  memset(msgKeys, 0, 4 * sizeof(unsigned char));

  for (; !mClosing;) {
    int    n      = 0;
    size_t it     = 0;
    size_t length = readLength;

    if (length > BUFSIZE) {
      length = BUFSIZE;
      readLength -= BUFSIZE;
    }

    do {
      if (client->bio != nullptr && client->ssl != nullptr) {
        n = BIO_read(client->bio, bufferRecv + it, length - it);

        if (SSL_get_error(client->ssl, n) == SSL_ERROR_ZERO_RETURN) {
          mClosing = true;
        }
        if ((n == 0) || (n == -1)) {
          continue;
        }
      } else {
        n = recv(client->socketId, bufferRecv + it, length - it, 0);

        if (n <= 0) {
          if (errno == ENOTCONN || errno == EBADF || errno == ECONNRESET) {
            mClosing = true;
          }
          continue;
        }
      }

      it += n;
    } while (it != length && !mClosing);

    if (mClosing) {
      continue;
    }

    // Decode message header
    switch (step) {
    case FIRSTBYTE:
      fin    = (bufferRecv[0] & 0x80) >> 7;
      rsv    = (bufferRecv[0] & 0x70) >> 4;
      opcode = bufferRecv[0] & 0xf;

      step       = LENGTH;
      readLength = 1;
      break;

    case LENGTH:
      if (!msgLength) {
        msgMask = (bufferRecv[0] & 0x80) >> 7;
        if (!msgMask) {
          closeRecv();
          return;
        }

        msgLength = bufferRecv[0] & 0x7f;
        if (!msgLength) {
          spdlog::warn("Websocket: Message length is null. Closing socket.");
          msgLength  = 0;
          msgContent = nullptr;
          step       = CONTENT;
          continue;
        }
        if (msgLength == 126) {
          readLength = 2;
          break;
        }
        if (msgLength == 127) {
          readLength = 8;
          break;
        }
      } else {
        if (msgLength == 126) {
          auto *tmp = (u_int16_t *)bufferRecv;
          msgLength = ntohs(*tmp);
        }
        if (msgLength == 127) {
          auto *tmp = (u_int64_t *)bufferRecv;
          msgLength = ntohll(*tmp);
        }
      }

      if ((msgContent = (unsigned char *)malloc(msgLength * sizeof(unsigned char))) == nullptr) {
        char logBuffer[500];
        snprintf(logBuffer, 500, " Websocket: Message content allocation failed (length: %llu)",
                 static_cast<unsigned long long>(msgLength));
        spdlog::warn(logBuffer);
        msgContent = nullptr;
      }
      msgContentIt = 0;
      if (msgMask) {
        step       = MASK;
        readLength = 4;
      } else {
        step       = CONTENT;
        readLength = msgLength;
      }
      break;

    case MASK:
      memcpy(msgKeys, bufferRecv, 4 * sizeof(unsigned char));
      readLength = msgLength;
      step       = CONTENT;
      break;

    case CONTENT:
      char buf3[300];
      snprintf(buf3, 300,
               "WebSocket: new message received (len=%llu fin=%d "
               "rsv=%d opcode=%d mask=%d)",
               static_cast<unsigned long long>(msgLength), fin, rsv, opcode, msgMask);
      spdlog::debug(buf3);
      if (msgContent != nullptr) {
        for (size_t i = 0; i < length; i++) {
          if (msgMask) {
            msgContent[msgContentIt] = bufferRecv[i] ^ msgKeys[msgContentIt % 4];
          } else {
            msgContent[msgContentIt] = bufferRecv[i];
          }

          msgContentIt++;
        }
      }

      if (msgContentIt == msgLength) {
        if (msgContent != nullptr && (client->compression == ZLIB) && (rsv & 4)) {
          try {
            unsigned char *msg = nullptr;
            size_t msgLen = nvj_gunzip_websocket_v2(&msg, msgContent, msgLength, true, gzipcontext.z_dictionary_inflate,
                                                    &(gzipcontext.dictInfLength));
            free(msgContent);
            msgContent = msg;
            msgLength  = msgLen;

            msgContent[msgLength] = '\0';
          } catch (std::exception &e) {
            spdlog::error("Websocket: nvj_gzip raised an exception: {}", e.what());
            msgLength = 0;
          }
        }

        switch (opcode) {
        case 0x1:
          if (msgLength) {
            mWebsocket->onTextMessage(this, std::string((char *)msgContent, msgLength), fin);
          } else {
            mWebsocket->onTextMessage(this, "", fin);
          }
          break;
        case 0x2:
          mWebsocket->onBinaryMessage(this, msgContent, msgLength, fin);
          break;
        case 0x8:
          if (mWebsocket->onCloseCtrlFrame(this, msgContent, msgLength)) {
            sendCloseCtrlFrame(msgContent, msgLength);
            closeRecv();
            return;
          }
          break;
        case 0x9:
          if (mWebsocket->onPingCtrlFrame(this, msgContent, msgLength)) {
            sendPongCtrlFrame(msgContent, msgLength);
          }
          break;
        case 0xa:
          mWebsocket->onPongCtrlFrame(this, msgContent, msgLength);
          break;
        default:
          spdlog::info("WebSocket: message received with unknown opcode ({}) has been ignored", opcode);
          break;
        }

        if ((client->compression == ZLIB) && (rsv & 4) && msgLength) {
          free(msgContent);
        }

        fin          = false;
        rsv          = 0;
        opcode       = 0;
        msgLength    = 0;
        msgContentIt = 0;
        msgMask      = false;
        memset(msgKeys, 0, 4 * sizeof(unsigned char));
        msgContent = nullptr;
        readLength = 1;
        step       = FIRSTBYTE;
      }
      break;
    }
  }
}

/***********************************************************************/

void WebSocketClient::closeWS() {
  GR_JUMP_TRACE;
  mClosing = true;
  mWebsocket->removeClient(this, true);
  mWebsocket->onClosing(this);

  pthread_cond_broadcast(&sendingNotification);
  wait_for_thread(mSendingThreadId);
  WebServer::freeClientSockData(mRequest->getClientSockData());
  wait_for_thread(mReceivingThreadId);
  restoreSessionExpiration(mRequest);
  delete mRequest;
  delete this;
}

void WebSocketClient::closeSend() {
  GR_JUMP_TRACE;
  mClosing = true;
  mWebsocket->removeClient(this, false);
  mWebsocket->onClosing(this);

  WebServer::freeClientSockData(mRequest->getClientSockData());
  restoreSessionExpiration(mRequest);
  delete mRequest;
  delete this;
}

void WebSocketClient::closeRecv() {
  GR_JUMP_TRACE;
  mClosing = true;
  mWebsocket->removeClient(this, false);
  mWebsocket->onClosing(this);

  pthread_cond_broadcast(&sendingNotification);
  wait_for_thread(mSendingThreadId);
  WebServer::freeClientSockData(mRequest->getClientSockData());
  restoreSessionExpiration(mRequest);
  delete mRequest;
  delete this;
}

/***********************************************************************/

void WebSocketClient::noSessionExpiration(HttpRequest *request) {
  GR_JUMP_TRACE;
  std::string sessionId = request->getSessionId();
  if (sessionId != "") {
    HttpSession::noExpiration(request->getSessionId());
  }
}

void WebSocketClient::restoreSessionExpiration(HttpRequest *request) {
  GR_JUMP_TRACE;
  std::string sessionId = request->getSessionId();
  if (sessionId != "") {
    HttpSession::updateExpiration(request->getSessionId());
  }
}

/***********************************************************************/

bool WebSocketClient::sendMessage(const MessageContent *msgContent) {
  GR_JUMP_TRACE;
  ClientSockData *client = mRequest->getClientSockData();

  unsigned char  headerBuffer[10]; // 10 is the max header size
  size_t         headerLen = 2;    // default header size
  unsigned char *msg       = nullptr;
  size_t         msgLen    = 0;
  bool           result    = true;

  if (client == nullptr) {
    return false;
  }

  headerBuffer[0] = 0x80 | (msgContent->opcode & 0xf); // FIN & OPCODE:0x1
  if (client->compression == ZLIB) {
    headerBuffer[0] |= 0x40; // Set RSV1
    try {
      msgLen = nvj_gzip_websocket_v2(&msg, msgContent->message, msgContent->length, &(gzipcontext.strm_deflate));
    } catch (...) {
      spdlog::error("Websocket: nvj_gzip raised an exception");
      return false;
    }
  } else {
    msg    = msgContent->message;
    msgLen = msgContent->length;
  }

  if (msgLen < 126) {
    headerBuffer[1] = msgLen;
  } else {
    if (msgLen < 0xFFFF) {
      headerBuffer[1]                  = 126;
      *(u_int16_t *)(headerBuffer + 2) = htons((u_int16_t)msgLen);
      headerLen += 2;
    } else {
      headerBuffer[1]                  = 127;
      *(u_int64_t *)(headerBuffer + 2) = htonll((u_int64_t)msgLen);
      headerLen += 8;
    }
  }

  if (!WebServer::httpSend(client, headerBuffer, headerLen) || !WebServer::httpSend(client, msg, msgLen)) {
    result = false;
  }

  if (client->compression == ZLIB) {
    free(msg);
  }

  return result;
}

/***********************************************************************/

void WebSocketClient::addSendingQueue(MessageContent *msgContent) {
  GR_JUMP_TRACE;
  pthread_mutex_lock(&sendingQueueMutex);
  if (!mClosing) {
    sendingQueue.push(msgContent);
  }
  pthread_mutex_unlock(&sendingQueueMutex);
  pthread_cond_broadcast(&sendingNotification);
}

/***********************************************************************/

void WebSocketClient::sendTextMessage(const std::string &message, bool fin) {
  GR_JUMP_TRACE;
  auto *msgContent    = (MessageContent *)malloc(sizeof(MessageContent));
  msgContent->opcode  = 0x1;
  msgContent->message = (unsigned char *)malloc(message.length() * sizeof(char));
  message.copy((char *)msgContent->message, message.length());
  msgContent->length = message.length();
  msgContent->fin    = fin;
  msgContent->date_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
          .count();
  addSendingQueue(msgContent);
}

/***********************************************************************/

void WebSocketClient::sendBinaryMessage(const unsigned char *message, size_t length, bool fin) {
  GR_JUMP_TRACE;
  auto *msgContent    = (MessageContent *)malloc(sizeof(MessageContent));
  msgContent->opcode  = 0x2;
  msgContent->message = (unsigned char *)malloc(length * sizeof(unsigned char));
  memcpy(msgContent->message, message, length);
  msgContent->length = length;
  msgContent->fin    = fin;
  msgContent->date_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
          .count();
  addSendingQueue(msgContent);
}

/***********************************************************************/

void WebSocketClient::sendPingCtrlFrame(const unsigned char *message, size_t length) {
  GR_JUMP_TRACE;
  auto *msgContent    = (MessageContent *)malloc(sizeof(MessageContent));
  msgContent->opcode  = 0x9;
  msgContent->message = (unsigned char *)malloc(length * sizeof(unsigned char));
  memcpy(msgContent->message, message, length);
  msgContent->length = length;
  msgContent->fin    = true;
  msgContent->date_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
          .count();
  addSendingQueue(msgContent);
}

void WebSocketClient::sendPingCtrlFrame(const std::string &message) {
  GR_JUMP_TRACE;
  sendPingCtrlFrame((const unsigned char *)message.c_str(), message.length());
}

/***********************************************************************/

void WebSocketClient::sendPongCtrlFrame(const unsigned char *message, size_t length) {
  GR_JUMP_TRACE;
  auto *msgContent    = (MessageContent *)malloc(sizeof(MessageContent));
  msgContent->opcode  = 0xa;
  msgContent->message = (unsigned char *)malloc(length * sizeof(unsigned char));
  memcpy(msgContent->message, message, length);
  msgContent->length = length;
  msgContent->fin    = false;
  msgContent->date_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
          .count();

  addSendingQueue(msgContent);
}

void WebSocketClient::sendPongCtrlFrame(const std::string &message) {
  GR_JUMP_TRACE;
  sendPongCtrlFrame((const unsigned char *)message.c_str(), message.length());
}

/***********************************************************************/

void WebSocketClient::sendCloseCtrlFrame(const unsigned char *message, size_t length) {
  GR_JUMP_TRACE;
  auto *msgContent    = (MessageContent *)malloc(sizeof(MessageContent));
  msgContent->opcode  = 0x8;
  msgContent->message = (unsigned char *)malloc(length * sizeof(unsigned char));
  memcpy(msgContent->message, message, length);
  msgContent->length = length;
  msgContent->fin    = true;
  msgContent->date_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
          .count();

  addSendingQueue(msgContent);
}

void WebSocketClient::sendCloseCtrlFrame(const std::string &message) {
  GR_JUMP_TRACE;
  sendCloseCtrlFrame((const unsigned char *)message.c_str(), message.length());
}

/***********************************************************************/
