cmake_minimum_required(VERSION 3.18)

project(ServerCLI LANGUAGES CXX)

add_executable(ServerCLI Server.cpp)

target_include_directories(ServerCLI PRIVATE ${CMAKE_SOURCE_DIR}/Core/Server)
target_link_libraries(ServerCLI PRIVATE ServerCore)

install(TARGETS ServerCLI RUNTIME DESTINATION bin)
