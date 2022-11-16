/***************************************************************************
 *
 * Project         _____    __   ____   _      _
 *                (  _  )  /__\ (_  _)_| |_  _| |_
 *                 )(_)(  /(__)\  )( (_   _)(_   _)
 *                (_____)(__)(__)(__)  |_|    |_|
 *
 *
 * Copyright 2018-present, Leonid Stryzhevskyi <lganzzzo@gmail.com>
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

#ifndef oatpp_wolfSSL_Connection_hpp
#define oatpp_wolfSSL_Connection_hpp

#include "oatpp/core/provider/Provider.hpp"
#include "oatpp/core/data/stream/Stream.hpp"

#include "wolfssl/ssl.h"

namespace oatpp { namespace wolfssl {

/**
 * TLS Connection implementation based on wolfSSL. Extends &id:oatpp::data::stream::IOStream; and &id:oatpp::base::Countable.
 */
class Connection : public oatpp::base::Countable, public oatpp::data::stream::IOStream {

public:
  /**
   * Constructor.
   */
  Connection(WOLFSSL * sslSession, const provider::ResourceHandle<data::stream::IOStream>& stream);

  /**
   * Virtual destructor.
   */
  ~Connection();

  /**
   * Write operation callback.
   * @param data - pointer to data.
   * @param count - size of the data in bytes.
   * @param action - async specific action. If action is NOT &id:oatpp::async::Action::TYPE_NONE;, then
   * caller MUST return this action on coroutine iteration.
   * @return - actual number of bytes written. 0 - to indicate end-of-file.
   */
  oatpp::v_io_size write(const void *data, v_buff_size count, async::Action& action) override;

  /**
   * Set OutputStream I/O mode.
   * @param ioMode
   */
  void setOutputStreamIOMode(oatpp::data::stream::IOMode ioMode) override;

  /**
   * Set OutputStream I/O mode.
   * @return
   */
  oatpp::data::stream::IOMode getOutputStreamIOMode() override;

  /**
   * Get output stream context.
   * @return - &id:oatpp::data::stream::Context;.
   */
  oatpp::data::stream::Context& getOutputStreamContext() override;

  /**
   * Read operation callback.
   * @param buffer - pointer to buffer.
   * @param count - size of the buffer in bytes.
   * @param action - async specific action. If action is NOT &id:oatpp::async::Action::TYPE_NONE;, then
   * caller MUST return this action on coroutine iteration.
   * @return - actual number of bytes written to buffer. 0 - to indicate end-of-file.
   */
  oatpp::v_io_size read(void *buff, v_buff_size count, async::Action& action) override;

  /**
   * Set InputStream I/O mode.
   * @param ioMode
   */
  void setInputStreamIOMode(oatpp::data::stream::IOMode ioMode) override;

  /**
   * Get InputStream I/O mode.
   * @return
   */
  oatpp::data::stream::IOMode getInputStreamIOMode() override;

  /**
   * Get input stream context. <br>
   * @return - &id:oatpp::data::stream::Context;.
   */
  oatpp::data::stream::Context& getInputStreamContext() override;

  /**
   * Get the underlying transport stream.
   * @return
   */
  provider::ResourceHandle<data::stream::IOStream> getTransportStream();

  class ConnectionContext : public oatpp::data::stream::Context {
  private:
    Connection* m_connection;
    data::stream::StreamType m_streamType;
  public:

    ConnectionContext(Connection* connection, data::stream::StreamType streamType, Properties&& properties);

    void init() override;

    async::CoroutineStarter initAsync() override;

    bool isInitialized() const override;

    data::stream::StreamType getStreamType() const override;

  };

private:
  provider::ResourceHandle<data::stream::IOStream> m_stream;
  ConnectionContext* m_inContext;
  ConnectionContext* m_outContext;
  bool m_initialized;
  WOLFSSL *m_sslSession;

  static int CallbackIORecv(WOLFSSL *ssl, char *buf, int sz, void *ctx);
  static int CallbackIOSend(WOLFSSL *ssl, char *buf, int sz, void *ctx);
};

}}

#endif // oatpp_wolfSSL_Connection_hpp
