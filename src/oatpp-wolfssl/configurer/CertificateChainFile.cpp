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

#include "CertificateChainFile.hpp"

namespace oatpp { namespace wolfssl { namespace configurer {

CertificateChainFile::CertificateChainFile(const oatpp::String &fileName)
  : m_fileName(fileName)
{}

void CertificateChainFile::configure(WOLFSSL_CTX *ctx) {

    OATPP_LOGD("oatpp::wolfssl::Config", "FWH::ewew'");
  if (m_fileName->empty()) {
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
  }
  else
  {
    auto ret = wolfSSL_CTX_load_verify_locations(ctx, m_fileName->c_str(), nullptr);
    if (ret != WOLFSSL_SUCCESS)
    {
      OATPP_LOGE("[oatpp::wolfssl::configurer::CertificateChainFile::configure()]", "Error. Call to wolfSSL_CTX_load_verify_locations() returned %d", ret);
      throw std::runtime_error("[oatpp::wolfssl::configurer::CertificateChainFile::configure()]: Error. Call to wolfSSL_CTX_load_verify_locations() failed.");
    }
  }

    OATPP_LOGD("oatpp::wolfssl::Config", "FWH::32322323'");
}

}}}
