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

#ifndef oatpp_wolfSSL_Config_hpp
#define oatpp_wolfSSL_Config_hpp

#include <string>
#include <memory>

#include "wolfssl/ssl.h"

namespace oatpp { namespace wolfssl {

class Config {
private:
  WOLFSSL_CTX *m_sslCtx;

public:
  /**
   * Constructor needs an WOLFSSL_METHOD* hence default constructor is not allowed
   */
  Config() = delete;

  /**
   * Constructor.
   */
  Config(WOLFSSL_METHOD *protocolMethod);

  /**
   * Non-virtual destructor.
   */
  ~Config();

  /**
   * Create shared Config.
   * @return - `std::shared_ptr` to Config.
   */
  static std::shared_ptr<Config> createShared(WOLFSSL_METHOD *protocolMethod);

  /**
   * Create default server config.
   * @param serverCertFilePemFormat - server certificate in pem format.
   * @param privateKeyFilePemFormat - private key in pem format.
   * @param pkPassword - optional private key password.
   * @return - `std::shared_ptr` to Config.
   */
  static std::shared_ptr<Config> createDefaultServerConfigShared(const char* serverCertFilePemFormat, const char* privateKeyFilePemFormat, const char* pkPassword = nullptr);

  /**
   * Create default client config.
   * @param caRootCertFile - path to the CA Root certificate to verificate against
   * @return - `std::shared_ptr` to Config.
   */
  static std::shared_ptr<Config> createDefaultClientConfigShared(const char* caRootCertFile = nullptr);

  WOLFSSL_CTX *getTlsContext();
};

}}

#endif // oatpp_wolfSSL_Config_hpp
