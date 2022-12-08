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

#if defined(OATPP_WOLFSSL_DEBUG)
namespace oatpp { namespace wolfssl {
static void wolfsslDebug(const int logLevel, const char* const logMessage) {
  OATPP_LOGD("[wolfssl]", "[%s] %s", logLevel, logMessage)
}
}}
#endif

namespace oatpp { namespace wolfssl {

Config::Config(WOLFSSL_METHOD *protocolMethod) {
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
}

Config::~Config() {
  wolfSSL_CTX_free(m_sslCtx);
}

std::shared_ptr<Config> Config::createShared(WOLFSSL_METHOD *protocolMethod) {
  return std::make_shared<Config>(protocolMethod);
}

std::shared_ptr<Config> Config::createDefaultServerConfigShared(const char* serverCertFilePemFormat, const char* privateKeyFilePemFormat, const char* pkPassword) {
  auto result = createShared(wolfTLS_server_method());

  auto res = wolfSSL_CTX_use_certificate_file(result->getTlsContext(), serverCertFilePemFormat, WOLFSSL_FILETYPE_PEM/*WOLFSSL_FILETYPE_PEM*/);
  if(res != WOLFSSL_SUCCESS) {
    OATPP_LOGD("[oatpp::wolfssl::Config::createDefaultServerConfigShared()]", "Error. Can't parse serverCertFilePemFormat path='%s', return value=%d", serverCertFilePemFormat, res);
    throw std::runtime_error("[oatpp::wolfssl::Config::createDefaultServerConfigShared()]: Error. Can't parse serverCertFilePemFormat");
  }

  if (pkPassword != nullptr) {
    OATPP_LOGD("[oatpp::wolfssl::Config::createDefaultServerConfigShared()]", "wolfSSL_CTX_set_default_passwd_cb_userdata()");
    wolfSSL_CTX_set_default_passwd_cb_userdata(result->getTlsContext(), (void*)pkPassword);
  }

  res = wolfSSL_CTX_use_PrivateKey_file(result->getTlsContext(), privateKeyFilePemFormat, WOLFSSL_FILETYPE_PEM/*WOLFSSL_FILETYPE_PEM*/);
  if(res != WOLFSSL_SUCCESS) {
    OATPP_LOGD("[oatpp::wolfssl::Config::createDefaultServerConfigShared()]", "Error. Can't parse privateKeyFilePemFormat path='%s', return value=%d", privateKeyFilePemFormat, res);
    throw std::runtime_error("[oatpp::wolfssl::Config::createDefaultServerConfigShared()]: Error. Can't parse privateKeyFilePemFormat");
  }

  return result;
}

std::shared_ptr<Config> Config::createDefaultClientConfigShared(const char* caRootCertFile) {
  auto result = createShared(wolfTLS_client_method());

  if (caRootCertFile == nullptr) {
    wolfSSL_CTX_set_verify(result->getTlsContext(), SSL_VERIFY_NONE, 0);
  }
  else
  {
    auto ret = wolfSSL_CTX_load_verify_locations(result->getTlsContext(), caRootCertFile, nullptr);
    if (ret != SSL_SUCCESS)
    {
      OATPP_LOGE("[oatpp::wolfssl::Config::createDefaultClientConfigShared()]", "Error. Call to wolfSSL_CTX_load_verify_locations() returned %d", ret);
      throw std::runtime_error("[oatpp::wolfssl::Config::createDefaultClientConfigShared()]: Error. Call to wolfSSL_CTX_load_verify_locations() failed.");
    }
  }

  return result;
}

std::shared_ptr<Config> Config::createDefaultClientConfigShared(bool, std::string caRootCert, std::string clientCert, std::string privateKey) {
  auto result = createShared(wolfTLS_client_method());
  int ret = WOLFSSL_SUCCESS;
  if (caRootCert.size() == 0)
  {
    wolfSSL_CTX_set_verify(result->getTlsContext(), SSL_VERIFY_NONE, 0);
  }
  else
  {
    ret = wolfSSL_CTX_load_verify_buffer(result->getTlsContext(), (const unsigned char *) caRootCert.data(), caRootCert.size() + 1, WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS)
    {
      OATPP_LOGE("[oatpp::wolfssl::Config::createDefaultClientConfigShared()]", "Error. Call to wolfSSL_CTX_load_verify_buffer() returned %d", ret);
      throw std::runtime_error("[oatpp::wolfssl::Config::createDefaultClientConfigShared()]: Error. Call to wolfSSL_CTX_load_verify_buffer() failed.");
    }
  }

  if (clientCert.size() != 0) {
    ret = wolfSSL_CTX_use_certificate_buffer(result->getTlsContext(), (const unsigned char *) clientCert.data(), clientCert.size() + 1, WOLFSSL_FILETYPE_PEM/*WOLFSSL_FILETYPE_PEM*/);
    if(ret != WOLFSSL_SUCCESS) {
      OATPP_LOGD("[oatpp::wolfssl::Config::createDefaultClientConfigShared()]", "Error. Call to wolfSSL_CTX_use_certificate_buffer return value=%d", ret);
      throw std::runtime_error("[oatpp::wolfssl::Config::createDefaultClientConfigShared()]: Error. Can't parse serverCertFilePemFormat");
    }
  }

  if (privateKey.size() != 0) {
    ret = wolfSSL_CTX_use_PrivateKey_buffer(result->getTlsContext(), (const unsigned char *) privateKey.data(), privateKey.size() + 1, WOLFSSL_FILETYPE_PEM/*WOLFSSL_FILETYPE_PEM*/);
    if(ret != WOLFSSL_SUCCESS) {
      OATPP_LOGD("[oatpp::wolfssl::Config::createDefaultClientConfigShared()]", "Error. Call to wolfSSL_CTX_use_PrivateKey_buffer, return value=%d", ret);
      throw std::runtime_error("[oatpp::wolfssl::Config::createDefaultClientConfigShared()]: Error. Can't parse privateKeyFilePemFormat");
    }
  }

  return result;
}

WOLFSSL_CTX *Config::getTlsContext() {
  return m_sslCtx;
}

}}