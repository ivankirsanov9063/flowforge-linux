cmake_minimum_required(VERSION 3.18)

project(ClientCLI LANGUAGES CXX)

add_executable(ClientCLI Client.cpp)

target_include_directories(ClientCLI PRIVATE ${CMAKE_SOURCE_DIR}/Core/Client)
target_link_libraries(ClientCLI PRIVATE ClientCore)

install(TARGETS ClientCLI RUNTIME DESTINATION bin)
