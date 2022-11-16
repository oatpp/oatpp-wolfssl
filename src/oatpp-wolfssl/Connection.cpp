/***************************************************************************
 *
 * Project         _____    __   ____   _      _
 *                (  _  )  /__\ (_  _)_| |_  _| |_
 *                 )(_)(  /(__)\  )( (_   _)(_   _)
 *                (_____)(__)(__)(__)  |_|    |_|
 *
 *
 * Copyright 2022-present, Leonid Stryzhevskyi <lganzzzo@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#include "Connection.hpp"

#include <thread>
#include <chrono>

#include "wolfssl/ssl.h"

namespace oatpp { namespace wolfssl {

Connection::ConnectionContext::ConnectionContext(Connection* connection, data::stream::StreamType streamType, Properties&& properties)
  : Context(std::forward<Properties>(properties))
  , m_connection(connection)
  , m_streamType(streamType)
{}

int wolfSslHandshake(WOLFSSL *ssl) {
  return wolfSSL_GetSide(ssl) == WOLFSSL_CLIENT_END ? wolfSSL_connect(ssl) : wolfSSL_accept(ssl);
}

void Connection::ConnectionContext::init() {

  if(m_connection->m_initialized) {
    return;
  }
  auto sslSession = m_connection->m_sslSession;
  auto result = 0;

  while ((result = wolfSslHandshake(sslSession)) != WOLFSSL_SUCCESS)
  {
    auto error = wolfSSL_get_error(sslSession, result);
    if (error != WOLFSSL_ERROR_WANT_READ || error != WOLFSSL_ERROR_WANT_WRITE)
    {
      char buffer[80];
      OATPP_LOGE("[Connection::ConnectionContext::init()]", "Error. Call to wolfSSL_connect(%p): %s", sslSession, wolfSSL_ERR_error_string(error, buffer));
      break;
    }
  }

  m_connection->m_initialized = true;
}

async::CoroutineStarter Connection::ConnectionContext::initAsync() {

  class HandshakeCoroutine : public oatpp::async::Coroutine<HandshakeCoroutine> {
  private:
    Connection* m_connection;
  public:
    HandshakeCoroutine(Connection* connection)
      : m_connection(connection)
    {}

    Action act() override {
      return finish();
    }

    Action doInit() {
      return finish();
    }
  };

  if(m_connection->m_initialized) {
    return nullptr;
  }

  return HandshakeCoroutine::start(m_connection);
}

bool Connection::ConnectionContext::isInitialized() const {
  return m_connection->m_initialized;
}

data::stream::StreamType Connection::ConnectionContext::getStreamType() const {
  return m_streamType;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Connection

Connection::Connection(WOLFSSL * sslSession, const provider::ResourceHandle<data::stream::IOStream>& stream) : m_stream(stream), m_initialized(false), m_sslSession(sslSession)
{
  wolfSSL_SSLSetIORecv(m_sslSession, &Connection::CallbackIORecv);
  wolfSSL_SSLSetIOSend(m_sslSession, &Connection::CallbackIOSend);
  wolfSSL_SetIOReadCtx(m_sslSession, this);
  wolfSSL_SetIOWriteCtx(m_sslSession, this);

  auto &streamInContext = stream.object->getInputStreamContext();
  auto& streamOutContext = stream.object->getOutputStreamContext();

  data::stream::Context::Properties inProperties(streamInContext.getProperties());
  inProperties.put("tls", "wolfssl");
  inProperties.getAll();

  m_inContext = new ConnectionContext(this, streamInContext.getStreamType(), std::move(inProperties));

  if(streamInContext == streamOutContext) {
    m_outContext = m_inContext;
  } else {
    data::stream::Context::Properties outProperties(streamOutContext.getProperties());
    outProperties.put("tls", "wolfssl");
    outProperties.getAll();

    m_outContext = new ConnectionContext(this, streamOutContext.getStreamType(), std::move(outProperties));
  }
}

Connection::~Connection(){
  if(m_inContext == m_outContext) {
    delete m_inContext;
  } else {
    delete m_inContext;
    delete m_outContext;
  }

  wolfSSL_free(m_sslSession);
}

/* Write data from oatpp to wolfssl */
v_io_size Connection::write(const void *buff, v_buff_size count, async::Action& action) {
  auto result = wolfSSL_write(m_sslSession, buff, count);
  if(result <= 0) {
    switch(wolfSSL_get_error(m_sslSession, result)) {
      case WOLFSSL_ERROR_WANT_READ:   return oatpp::IOError::RETRY_WRITE;
      case WOLFSSL_ERROR_WANT_WRITE:  return oatpp::IOError::RETRY_WRITE;
      default:                        return oatpp::IOError::BROKEN_PIPE;
    }
  }
  return result;
}

/* Read data from oatpp to wolfssl */
v_io_size Connection::read(void *buff, v_buff_size count, async::Action& action) {
  auto result = wolfSSL_read(m_sslSession, buff, count);
  if(result <= 0) {
    switch(wolfSSL_get_error(m_sslSession, result)) {
      case WOLFSSL_ERROR_WANT_READ:   return oatpp::IOError::RETRY_READ;
      case WOLFSSL_ERROR_WANT_WRITE:  return oatpp::IOError::RETRY_READ;
      default:                        return oatpp::IOError::BROKEN_PIPE;
    }
  }
  return result;
}

void Connection::setOutputStreamIOMode(oatpp::data::stream::IOMode ioMode) {
  m_stream.object->setOutputStreamIOMode(ioMode);
}

oatpp::data::stream::IOMode Connection::getOutputStreamIOMode() {
  return m_stream.object->getOutputStreamIOMode();
}

oatpp::data::stream::Context& Connection::getOutputStreamContext() {
  return *m_outContext;
}

void Connection::setInputStreamIOMode(oatpp::data::stream::IOMode ioMode) {
  m_stream.object->setInputStreamIOMode(ioMode);
}

oatpp::data::stream::IOMode Connection::getInputStreamIOMode() {
  return m_stream.object->getInputStreamIOMode();
}

oatpp::data::stream::Context& Connection::getInputStreamContext() {
  return *m_inContext;
}

provider::ResourceHandle<data::stream::IOStream> Connection::getTransportStream() {
  return m_stream;
}

/* Read data from wolfSSL to oatpp */
int Connection::CallbackIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  auto connection = static_cast<oatpp::wolfssl::Connection *>(ctx);
  async::Action action;
  auto res = connection->m_stream.object->read(buf, sz, action);
  if(res == IOError::RETRY_READ || res == IOError::RETRY_WRITE) {
    return WOLFSSL_ERROR_WANT_READ;
  }
  return res;
}

/* Write data from wolfSSL to oatpp */
int Connection::CallbackIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
  auto connection = static_cast<oatpp::wolfssl::Connection *>(ctx);
  async::Action action;
  auto res = connection->m_stream.object->write(buf, sz, action);
  if(res == IOError::RETRY_READ || res == IOError::RETRY_WRITE) {
    return WOLFSSL_ERROR_WANT_WRITE;
  }
  return res;
}

}}
