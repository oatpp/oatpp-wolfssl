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

#include "Config.hpp"

#include "oatpp/core/base/Environment.hpp"

#include "wolfssl/ssl.h"

#include "configurer/CertificateChainFile.hpp"
#include "configurer/CertificateChainFileBuffer.hpp"
#include "configurer/CertificateFile.hpp"
#include "configurer/CertificateFileBuffer.hpp"
#include "configurer/PrivateKeyFile.hpp"
#include "configurer/PrivateKeyFileBuffer.hpp"

#if defined(OATPP_WOLFSSL_DEBUG)
namespace oatpp { namespace wolfssl {
static void wolfsslDebug(const int logLevel, const char* const logMessage) {
  OATPP_LOGD("[wolfssl]", "[%s] %s", logLevel, logMessage)
}
}}
#endif

namespace oatpp { namespace wolfssl {

Config::Config(WOLFSSL_METHOD *protocolMethod, const std::list<std::shared_ptr<configurer::ContextConfigurer>> &configurationItems) {
  static int res = wolfSSL_Init();
  if (res != SSL_SUCCESS) {
    OATPP_LOGD("[oatpp::wolfssl::Config::Config()]", "Error. Call to wolfSSL_init() failed. Return value=%d", res);
    throw std::runtime_error("[oatpp::wolfssl::Config::Config()]: Error. Call to wolfSSL_init() failed.");
  }

  m_sslCtx = wolfSSL_CTX_new(protocolMethod);
  if (m_sslCtx == nullptr) {
    OATPP_LOGE("[oatpp::wolfssl::Config::Config()]", "Error. Call to wolfSSL_CTX_new() returned NULL");
    throw std::runtime_error("[oatpp::wolfssl::Config::Config()]: Error. Call to wolfSSL_CTX_new() failed.");
  }

#if defined(OATPP_WOLFSSL_DEBUG)
  int ret = wolfSSL_SetLoggingCb(wolfsslDebug);
  if(ret != 0) {
    OATPP_LOGE("[oatpp::wolfssl::Config::Config()]", "Error. Call to wolfSSL_SetLoggingCb() returned %d", ret);
    throw std::runtime_error("[oatpp::wolfssl::Config::Config()]: Error. Call to wolfSSL_SetLoggingCb() failed.");
  }
  wolfSSL_Debugging_ON();
#endif

  for (auto& configItem : configurationItems) {
    configItem->configure(m_sslCtx);
  }
}

Config::~Config() {
  wolfSSL_CTX_free(m_sslCtx);
}

std::shared_ptr<Config> Config::createShared(WOLFSSL_METHOD *protocolMethod, const std::list<std::shared_ptr<configurer::ContextConfigurer>> &configurationItems) {
  return std::make_shared<Config>(protocolMethod, configurationItems);
}

std::shared_ptr<Config> Config::createDefaultServerConfigShared(const oatpp::String& serverCertFilePemFormat, const oatpp::String& privateKeyFilePemFormat, const char* pkPassword) {
  std::list<std::shared_ptr<configurer::ContextConfigurer>> configurationItems;

  configurationItems.push_back(std::make_shared<configurer::PrivateKeyFile>(privateKeyFilePemFormat, pkPassword));
  configurationItems.push_back(std::make_shared<configurer::CertificateFile>(serverCertFilePemFormat));

  return createShared(wolfTLS_server_method(), configurationItems);
}

std::shared_ptr<Config> Config::createDefaultClientConfigShared(const oatpp::String& caRootCertFile) {
  std::list<std::shared_ptr<configurer::ContextConfigurer>> configurationItems;

  configurationItems.push_back(std::make_shared<configurer::CertificateChainFile>(caRootCertFile));

  return createShared(wolfTLS_client_method(), configurationItems);
}

std::shared_ptr<Config> Config::createDefaultClientConfigShared(std::string caRootCert, std::string clientCert, std::string privateKey) {
  std::list<std::shared_ptr<configurer::ContextConfigurer>> configurationItems;

  configurationItems.push_back(std::make_shared<configurer::CertificateChainFileBuffer>(caRootCert));
  configurationItems.push_back(std::make_shared<configurer::PrivateKeyFileBuffer>(privateKey));
  configurationItems.push_back(std::make_shared<configurer::CertificateFileBuffer>(clientCert));

  return createShared(wolfTLS_client_method(), configurationItems);
}

WOLFSSL_CTX *Config::getTlsContext() {
  return m_sslCtx;
}

}}