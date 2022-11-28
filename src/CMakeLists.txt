
add_library(${OATPP_THIS_MODULE_NAME}
        oatpp-wolfssl/Config.hpp
        oatpp-wolfssl/Config.cpp        
        oatpp-wolfssl/Connection.hpp
        oatpp-wolfssl/Connection.cpp
        oatpp-wolfssl/client/ConnectionProvider.hpp
        oatpp-wolfssl/client/ConnectionProvider.cpp
        oatpp-wolfssl/server/ConnectionProvider.hpp
        oatpp-wolfssl/server/ConnectionProvider.cpp
)

set_target_properties(${OATPP_THIS_MODULE_NAME} PROPERTIES
        CXX_STANDARD 11
        CXX_EXTENSIONS OFF
        CXX_STANDARD_REQUIRED ON
)

if(OATPP_MODULES_LOCATION STREQUAL OATPP_MODULES_LOCATION_EXTERNAL)
    add_dependencies(${OATPP_THIS_MODULE_NAME} ${LIB_OATPP_EXTERNAL})
endif()

target_link_oatpp(${OATPP_THIS_MODULE_NAME})

target_include_directories(${OATPP_THIS_MODULE_NAME}
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

#######################################################################################################
## link wolfssl
target_include_directories(
        ${OATPP_THIS_MODULE_NAME}
        PUBLIC $<BUILD_INTERFACE:${WOLFSSL_INCLUDE_DIR}>
)

target_link_libraries(
        ${OATPP_THIS_MODULE_NAME}
        PRIVATE wolfssl::TLS
)

target_compile_definitions(
        ${OATPP_THIS_MODULE_NAME} 
        PUBLIC "-DHAVE_SNI"
)
if(${OATPP_WOLFSSL_DEBUG})
    target_compile_definitions(
        ${OATPP_THIS_MODULE_NAME} 
        PUBLIC "OATPP_WOLFSSL_DEBUG=${OATPP_WOLFSSL_DEBUG}")
endif()

#######################################################################################################
## install targets

if(OATPP_INSTALL)
    include("../cmake/module-install.cmake")
endif()
