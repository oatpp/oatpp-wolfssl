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

#ifndef oatpp_test_web_FullAsyncClientTest_hpp
#define oatpp_test_web_FullAsyncClientTest_hpp

#include "oatpp-test/UnitTest.hpp"

namespace oatpp { namespace test { namespace wolfssl {

class FullAsyncClientTest : public UnitTest {
private:
  v_uint16 m_port;
  v_int32 m_connectionsPerEndpoint;
public:

  FullAsyncClientTest(v_uint16 port, v_int32 connectionsPerEndpoint)
    : UnitTest("TEST[web::FullAsyncClientTest]")
    , m_port(port)
    , m_connectionsPerEndpoint(connectionsPerEndpoint)
  {}

  void onRun() override;

};

}}}

#endif /* oatpp_test_web_FullAsyncClientTest_hpp */
