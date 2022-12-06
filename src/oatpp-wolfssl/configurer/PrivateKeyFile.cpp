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

#include "PrivateKeyFile.hpp"

namespace oatpp { namespace wolfssl { namespace configurer {

PrivateKeyFile::PrivateKeyFile(const oatpp::String &fileName, const char *filePassword, int fileType)
  : m_fileName(fileName)
  , m_filePassword(filePassword)
  , m_fileType(fileType)
{}

void PrivateKeyFile::configure(WOLFSSL_CTX *ctx) {
  if (m_filePassword != nullptr) {
    OATPP_LOGD("[oatpp::wolfssl::configurer::PrivateKeyFile::configure()]", "wolfSSL_CTX_set_default_passwd_cb_userdata()");
    wolfSSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)m_filePassword);
  }

  auto res = wolfSSL_CTX_use_PrivateKey_file(ctx, m_fileName->c_str(), m_fileType/*WOLFSSL_FILETYPE_PEM*/);
  if(res != WOLFSSL_SUCCESS) {
    OATPP_LOGE("[oatpp::wolfssl::configurer::PrivateKeyFile::configure()]", "Error. Can't parse m_fileName path='%s', return value=%d", m_fileName->c_str(), res);
    throw std::runtime_error("[oatpp::wolfssl::configurer::PrivateKeyFile::configure()]: Error. Can't parse m_fileName");
  }
}

}}}

