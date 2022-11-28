#[=======================================================================[

Copyright (c) 2022 Benedikt-Alexander Mokroß <bam@icognize.de>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

FindwolfSSL
------------

Find the wolfSSL library.

Optional Components
^^^^^^^^^^^^^^^^^^^

This module supports two optional components: SSL and TLS.  Both
components have associated imported targets, as described below.

Imported Targets
^^^^^^^^^^^^^^^^

This module defines the following imported targets:

wolfssl::TLS
    The wolfSSL tls library, if found.

Result Variables
^^^^^^^^^^^^^^^^

This module will set the following variables in your project:

WOLFSSL_FOUND
    System has the wolfSSL library. If no components are requested it only requires the crypto library.
WOLFSSL_INCLUDE_DIR
    The wolfSSL include directory.
WOLFSSL_TLS_LIBRARY
    The wolfSSL TLS library.
WOLFSSL_LIBRARIES
    All wolfSSL libraries.
WOLFSSL_VERSION
    This is set to $major.$minor.$revision (e.g. 2.6.8).

Hints
^^^^^

Set WOLFSSL_ROOT_DIR to the root directory of an wolfSSL installation.

]=======================================================================]

# Set Hints
set(
    _WOLFSSL_ROOT_HINTS
    ${WOLFSSL_ROOT_DIR}
    ENV WOLFSSL_ROOT_DIR
)

# Set Paths
set(_WOLFSSL_ROOT_PATHS "/usr/local/")

# Combine
set(
    _WOLFSSL_ROOT_HINTS_AND_PATHS
    HINTS ${_WOLFSSL_ROOT_HINTS}
    PATHS ${_WOLFSSL_ROOT_PATHS}
)

# Find Include Path
find_path(
    WOLFSSL_INCLUDE_DIR
    NAMES wolfssl
    ${_WOLFSSL_ROOT_HINTS_AND_PATHS}
    PATH_SUFFIXES include
)

# Find SSL Library
find_library(
    WOLFSSL_TLS_LIBRARY
    NAMES libwolfssl wolfssl
    NAMES_PER_DIR ${_WOLFSSL_ROOT_HINTS_AND_PATHS}
    PATH_SUFFIXES lib
)

# Set Libraries
set(WOLFSSL_LIBRARIES ${WOLFSSL_CRYPTO_LIBRARY} ${WOLFSSL_X509_LIBRARY} ${WOLFSSL_SSL_LIBRARY} ${WOLFSSL_TLS_LIBRARY})

# Mark Variables As Advanced
mark_as_advanced(WOLFSSL_INCLUDE_DIR WOLFSSL_LIBRARIES WOLFSSL_CRYPTO_LIBRARY WOLFSSL_X509_LIBRARY WOLFSSL_SSL_LIBRARY WOLFSSL_TLS_LIBRARY)

# Find Version File
if(WOLFSSL_INCLUDE_DIR AND EXISTS "${WOLFSSL_INCLUDE_DIR}/wolfssl/version.h")

    # Get Version From File
    file(STRINGS "${WOLFSSL_INCLUDE_DIR}/wolfssl/version.h" VERSIONH REGEX "#define LIBWOLFSSL_VERSION_STRING[ ]+\".*\"")

    # Match Version String
    string(REGEX REPLACE ".*\".*([0-9]+)\\.([0-9]+)\\.([0-9]+)\"" "\\1;\\2;\\3" WOLFSSL_VERSION_LIST "${VERSIONH}")

    # Split Parts
    list(GET WOLFSSL_VERSION_LIST 0 WOLFSSL_VERSION_MAJOR)
    list(GET WOLFSSL_VERSION_LIST 1 WOLFSSL_VERSION_MINOR)
    list(GET WOLFSSL_VERSION_LIST 2 WOLFSSL_VERSION_REVISION)

    # Set Version String
    set(WOLFSSL_VERSION "${WOLFSSL_VERSION_MAJOR}.${WOLFSSL_VERSION_MINOR}.${WOLFSSL_VERSION_REVISION}")

    message(STATUS "oatpp-wolfssl: wolfSSL version ${WOLFSSL_VERSION}")

endif()

# Set Find Package Arguments
find_package_handle_standard_args(
    wolfSSL
    REQUIRED_VARS WOLFSSL_TLS_LIBRARY WOLFSSL_INCLUDE_DIR
    VERSION_VAR WOLFSSL_VERSION
    HANDLE_COMPONENTS
    FAIL_MESSAGE "Could NOT find wolfSSL, try setting the path to wolfSSL using the WOLFSSL_ROOT_DIR environment variable"
)

# wolfSSL Found
if(WOLFSSL_FOUND)
    # Set wolfssl::TLS
    if(NOT TARGET wolfssl::TLS AND EXISTS "${WOLFSSL_TLS_LIBRARY}")
        add_library(wolfssl::TLS UNKNOWN IMPORTED)
        set_target_properties(
            wolfssl::TLS
            PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${WOLFSSL_INCLUDE_DIR}"
            IMPORTED_LINK_INTERFACE_LANGUAGES "C"
            IMPORTED_LOCATION "${WOLFSSL_TLS_LIBRARY}"
        )
    endif() # wolfssl::TLS
endif(WOLFSSL_FOUND)
