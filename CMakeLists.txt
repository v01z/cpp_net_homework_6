cmake_minimum_required(VERSION 3.22)
project(homework_net_6v3)

set(CMAKE_CXX_STANDARD 17)

add_executable(server server.cpp err_decode.cpp)
add_executable(client client.cpp err_decode.cpp)

set(NECESSARY_FILES ${CMAKE_CURRENT_SOURCE_DIR}/auth.txt
    ${CMAKE_CURRENT_SOURCE_DIR}/key.pem
    ${CMAKE_CURRENT_SOURCE_DIR}/cert.pem)

add_custom_command(
        TARGET server POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        ${NECESSARY_FILES}
        ${CMAKE_CURRENT_BINARY_DIR})

find_package(OpenSSL REQUIRED)
target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto)

if(MINGW)
    target_link_libraries(server ws2_32)
    target_link_libraries(client ws2_32)
endif()
