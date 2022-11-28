# oatpp-wolfssl
Oatpp TLS adaptor for wolfSSL.

See more:
- [Oat++ Website](https://oatpp.io/)
- [Oat++ Github Repository](https://github.com/oatpp/oatpp)
- [wolfSSL](https://www.wolfssl.com/)

# THIS MODULE IS NOT READY TO USE

# oatpp-wolfssl [![Build Status](https://dev.azure.com/lganzzzo/lganzzzo/_apis/build/status/oatpp.oatpp-wolfssl?branchName=master)](https://dev.azure.com/lganzzzo/lganzzzo/_build/latest?definitionId=18&branchName=master)

**oatpp-wolfssl** - extension for [Oat++ Web Framework](https://github.com/oatpp/oatpp).  
It provides secure server and client connection providers for oatpp applications. Based on [wolfSSL](https://www.wolfssl.com/).  
Supports only "Simple" oatpp API.

See more:
- [Oat++ Website](https://oatpp.io/)
- [Oat++ Github Repository](https://github.com/oatpp/oatpp)
- [wolfSSL](https://www.wolfssl.com/)

## How To Build

### Requires

- wolfSSL installed.

### Build And Install oatpp-wolfssl

If wolfSSL was installed to a standard location:

```bash
cmake -B build -S .
cmake --build build
```

## APIs

### Server

#### ConnectionProvider

Create `ConnectionProvider`

```cpp
const char* serverCertificateFile = "path/to/server/certificate";
const char* serverPrivateKeyFile = "path/to/server/private/key";

/* Create Config */
auto config = oatpp::wolfssl::Config::createDefaultServerConfigShared(serverCertificateFile, serverPrivateKeyFile);

/* Create Secure Connection Provider */
auto connectionProvider = oatpp::wolfssl::server::ConnectionProvider::createShared(config, {"localhost" /* host */, 443 /* port */});

/* Get Secure Connection Stream */
auto connection = connectionProvider->getConnection();
```

#### Custom Transport Stream

Create `ConnectionProvider` with custom transport stream.

```cpp
const char* serverCertificateFile = "path/to/server/certificate";
const char* serverPrivateKeyFile = "path/to/server/private/key";

/* Create Config */
auto config = oatpp::wolfssl::Config::createDefaultServerConfigShared(serverCertificateFile, serverPrivateKeyFile);

/* Create Transport Stream Provider */
/* Replace With Your Custom Transport Stream Provider */
auto transportStreamProvider = oatpp::network::tcp::server::ConnectionProvider::createShared({"localhost" /* host */, 443 /* port */});

/* Create Secure Connection Provider */
auto connectionProvider = oatpp::wolfssl::server::ConnectionProvider::createShared(config, transportStreamProvider);

/* Get Secure Connection Stream over Custom Transport Stream */
auto connection = connectionProvider->getConnection();
```

**Note:** To use `oatpp-wolfssl` for server connections with custom transport stream you should implement:

- [oatpp::network::ServerConnectionProvider](https://oatpp.io/api/latest/oatpp/network/ConnectionProvider/#serverconnectionprovider).
- [oatpp::data::stream::IOStream](https://oatpp.io/api/latest/oatpp/core/data/stream/Stream/#iostream) - to be returned by `ConnectionProvider`.

### Client

#### ConnectionProvider

Create `ConnectionProvider`

```cpp
/* Create Config */
auto config = oatpp::wolfssl::Config::createDefaultClientConfigShared();

/* Create Secure Connection Provider */
auto connectionProvider = oatpp::wolfssl::client::ConnectionProvider::createShared(config, {"httpbin.org", 443 /* port */});

/* Get Secure Connection Stream */
auto connection = connectionProvider->getConnection();
```

#### Custom Transport Stream

Create `ConnectionProvider` with custom transport stream.

```cpp
/* Create Config */
auto config = oatpp::wolfssl::Config::createDefaultClientConfigShared();

/* Create Transport Stream Provider */
/* Replace With Your Custom Transport Stream Provider */
auto transportStreamProvider = oatpp::network::client::SimpleTCPConnectionProvider::createShared({"httpbin.org", 443 /* port */});

/* Create Secure Connection Provider */
auto connectionProvider = oatpp::wolfssl::client::ConnectionProvider::createShared(config, transportStreamProvider);

/* Get Secure Connection Stream over Custom Transport Stream */
auto connection = connectionProvider->getConnection();
```

**Note:** To use `oatpp-wolfssl` for client connections with custom transport stream you should implement:

- [oatpp::network::ClientConnectionProvider](https://oatpp.io/api/latest/oatpp/network/ConnectionProvider/#clientconnectionprovider).
- [oatpp::data::stream::IOStream](https://oatpp.io/api/latest/oatpp/core/data/stream/Stream/#iostream) - to be returned by `ConnectionProvider`.


## See more

- [oatpp-openssl](https://github.com/oatpp/oatpp-openssl)
- [oatpp-libressl](https://github.com/oatpp/oatpp-libressl)
- [oatpp-mbedtls](https://github.com/oatpp/oatpp-mbedtls)
