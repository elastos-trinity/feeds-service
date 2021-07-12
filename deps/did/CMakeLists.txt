project(did)

include(ExternalProject)

ExternalProject_Add(
    did

    PREFIX ${FEEDS_DEPS_BUILD_PREFIX}
    URL https://github.com/elastos/Elastos.DID.Native.SDK/archive/refs/tags/release-v2.0.0-pre.tar.gz
    URL_HASH SHA256=02c394aa8c52f6f3f8eb6a73bf15921e9f9097b1420e1009d07ab8c434e54d65
    DOWNLOAD_NAME did-v2.0-pre.zip
    DOWNLOAD_DIR ${FEEDS_DEPS_TARBALL_DIR}
    DOWNLOAD_NO_PROGRESS 1
    LOG_DOWNLOAD FALSE

    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${FEEDS_INT_DIST_DIR}
        -DENABLE_SHARED=FALSE
        -DENABLE_STATIC=TRUE
        -DENABLE_APPS=FALSE
        -DENABLE_TESTS=FALSE
        -DENABLE_DOCS=FALSE
        -DHDKEY_ONLY=FALSE
        -DENABLE_JWT=TRUE
        ${EXTERNAL_CMAKE_PROJECT_ADDITIONAL_ARGS}
)

add_library(libeladid-static INTERFACE)

if(WIN32)
    set(LIB_DECORATOR "_s")
else()
    set(LIB_DECORATOR "")
endif()

target_link_libraries(libeladid-static INTERFACE eladid${LIB_DECORATOR} hdkey${LIB_DECORATOR}
                                                 cjose jansson zip)

