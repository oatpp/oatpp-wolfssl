/***************************************************************************
 *
 * Project         _____    __   ____   _      _
 *                (  _  )  /__\ (_  _)_| |_  _| |_
 *                 )(_)(  /(__)\  )( (_   _)(_   _)
 *                (_____)(__)(__)(__)  |_|    |_|
 *
 *
 * Copyright 2018-present, Leonid Stryzhevskyi <lganzzzo@gmail.com>
 *                         Benedikt-Alexander Mokroß <bam@icognize.de>
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

#include "ConnectionProvider.hpp"

#include "oatpp/network/tcp/client/ConnectionProvider.hpp"
#include "oatpp/core/async/Coroutine.hpp"

#include "oatpp-wolfssl/Config.hpp"
#include "oatpp-wolfssl/Connection.hpp"

#include "wolfssl/ssl.h"

namespace oatpp { namespace wolfssl { namespace client {

void ConnectionProvider::ConnectionInvalidator::invalidate(const std::shared_ptr<data::stream::IOStream> &connection){
  auto c = std::static_pointer_cast<oatpp::wolfssl::Connection>(connection);

  /********************************************
   * WARNING!!!
   *
   * c->closeTLS(); <--- DO NOT
   *
   * DO NOT CLOSE or DELETE TLS handles here.
   * Remember - other threads can still be
   * waiting for TLS events.
   ********************************************/

  /* Invalidate underlying transport */
  auto s = c->getTransportStream();
  s.invalidator->invalidate(s.object);
}

ConnectionProvider::ConnectionProvider(
  const std::shared_ptr<Config>& config,
  const std::shared_ptr<oatpp::network::ClientConnectionProvider>& streamProvider
) : m_connectionInvalidator(std::make_shared<ConnectionInvalidator>())
  , m_streamProvider(streamProvider)
  , m_config(config)
{
  setProperty(PROPERTY_HOST, streamProvider->getProperty(PROPERTY_HOST).toString());
  setProperty(PROPERTY_PORT, streamProvider->getProperty(PROPERTY_PORT).toString());
}

ConnectionProvider::~ConnectionProvider() {
}

void ConnectionProvider::stop() {
  m_streamProvider->stop();
}

std::shared_ptr<ConnectionProvider> ConnectionProvider::createShared(
  const std::shared_ptr<Config>& config, 
  const network::Address& address
) {
  return createShared(config, network::tcp::client::ConnectionProvider::createShared(address));
}

std::shared_ptr<ConnectionProvider> ConnectionProvider::createShared(
  const std::shared_ptr<Config>& config,
  const std::shared_ptr<network::ClientConnectionProvider>& streamProvider
) {
  return std::shared_ptr<ConnectionProvider>(new ConnectionProvider(config, streamProvider));
}

provider::ResourceHandle<data::stream::IOStream> ConnectionProvider::get(){

  long flags = 0;
  auto stream = m_streamProvider->get();

  auto sslSession = wolfSSL_new(m_config->getTlsContext());
  if (sslSession == nullptr) {
    OATPP_LOGE("[oatpp::wolfssl::client::ConnectionProvider::get()]", "Error. Call to wolfSSL_new() returned NULL");
    throw std::runtime_error("[oatpp::wolfssl::client::ConnectionProvider::get()]: Error. Call to wolfSSL_new() failed.");
  }

  auto hostName = getProperty(PROPERTY_HOST).toString();
  auto res = wolfSSL_UseSNI(sslSession, WOLFSSL_SNI_HOST_NAME, hostName->c_str(), hostName->size());
  if (res != SSL_SUCCESS) {
    OATPP_LOGD("[oatpp::wolfssl::client::ConnectionProvider::get()]", "Error. Call to wolfSSL_UseSNI() failed. Return value=%d", res);
    throw std::runtime_error("[oatpp::wolfssl::client::ConnectionProvider::get()]: Error. Call to wolfSSL_UseSNI() failed.");
  }

  auto connection = std::make_shared<Connection>(sslSession, stream);
  connection->initContexts();

  flags = wolfSSL_get_verify_result(sslSession);
  if (flags != 0)
  {
    OATPP_LOGE("[oatpp::wolfssl::client::ConnectionProvider::get()]", "Server certificate verification failed. Return value=%d", flags);
    throw std::runtime_error("[oatpp::wolfssl::client::ConnectionProvider::get()]: Error. Server certificate verification failed.");
  }

  return provider::ResourceHandle<data::stream::IOStream>(connection, m_connectionInvalidator);

}

oatpp::async::CoroutineStarterForResult<const provider::ResourceHandle<data::stream::IOStream>&> ConnectionProvider::getAsync() {

  class ConnectCoroutine : public oatpp::async::CoroutineWithResult<ConnectCoroutine, const provider::ResourceHandle<data::stream::IOStream>&> {
  private:
    std::shared_ptr<ConnectionInvalidator> m_connectionInvalidator;
    std::shared_ptr<oatpp::network::ClientConnectionProvider> m_streamProvider;
  private:
    provider::ResourceHandle<data::stream::IOStream> m_stream;
    std::shared_ptr<Connection> m_connection;
  public:

    ConnectCoroutine(const std::shared_ptr<ConnectionInvalidator>& connectionInvalidator,
                     const std::shared_ptr<network::ClientConnectionProvider>& streamProvider)
      : m_connectionInvalidator(connectionInvalidator)
      , m_streamProvider(streamProvider)
    {
    }

    ~ConnectCoroutine() {
    }

    Action act() override {
      /* get transport stream */
      return Action::createActionByType(Action::TYPE_FINISH);
    }

    Action onConnected(const provider::ResourceHandle<data::stream::IOStream>& stream) {
      /* transport stream obtained */
      m_stream = stream;
      return Action::createActionByType(Action::TYPE_FINISH);
    }

    Action secureConnection() {
      return Action::createActionByType(Action::TYPE_FINISH);
    }

    Action verifyServerCertificate() {
      return Action::createActionByType(Action::TYPE_FINISH);
    }

    Action onSuccess() {
      return Action::createActionByType(Action::TYPE_FINISH);
    }


  };

  return ConnectCoroutine::startForResult(m_connectionInvalidator, m_streamProvider);

}

}}}
