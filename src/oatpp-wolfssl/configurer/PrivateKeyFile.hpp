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

#ifndef oatpp_wolfssl_configurer_PrivateKeyFile_hpp
#define oatpp_wolfssl_configurer_PrivateKeyFile_hpp

#include "ContextConfigurer.hpp"

#include "oatpp/core/Types.hpp"

namespace oatpp { namespace wolfssl { namespace configurer {

/**
 * Context configurer for private key file.
 * @extends &id:oatpp::wolfssl::configurer::ContextConfigurer;.
 */
class PrivateKeyFile : public ContextConfigurer {
private:
  oatpp::String m_fileName;
  int m_fileType;
  const char *m_filePassword;

public:
  /**
   * Constructor.
   * @param fileName
   * @param filePassword
   * @param fileType
   */
  PrivateKeyFile(const oatpp::String& fileName, const char *filePassword = nullptr, int fileType = WOLFSSL_FILETYPE_PEM);

  void configure(WOLFSSL_CTX* ctx) override;

};

}}}

#endif // oatpp_wolfssl_configurer_PrivateKeyFile_hpp
