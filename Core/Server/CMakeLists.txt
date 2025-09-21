# --- ServerCore ---
add_library(ServerCore SHARED
        Server.cpp
        Network.cpp
        NetworkRollback.cpp
        NetWatcher.cpp

        ${CMAKE_SOURCE_DIR}/Core/PluginWrapper.cpp
        ${CMAKE_SOURCE_DIR}/Core/TUN.cpp
        ${CMAKE_SOURCE_DIR}/Core/Logger.cpp
        ${CMAKE_SOURCE_DIR}/Core/Config.cpp
)

target_compile_features(ServerCore PRIVATE cxx_std_23)
target_include_directories(ServerCore PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

find_package(Boost REQUIRED
        COMPONENTS log log_setup filesystem thread regex date_time chrono atomic json container)
find_package(Threads REQUIRED)

# динамические boost-*.so
target_compile_definitions(ServerCore PRIVATE BOOST_ALL_DYN_LINK BOOST_LOG_DYN_LINK)

# ВАЖНО: все зависимости Boost.Log — PRIVATE к библиотеке
target_link_libraries(ServerCore
        PRIVATE
        Boost::log
        Boost::log_setup
        Boost::filesystem
        Boost::thread
        Boost::regex
        Boost::date_time
        Boost::chrono
        Boost::atomic
        Threads::Threads
        PUBLIC
        Boost::json      # если JSON в публичных заголовках
        Boost::container # убери, если не нужен в интерфейсе
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-route-3.0)
pkg_check_modules(NFT REQUIRED libnftables)
target_include_directories(ServerCore PRIVATE ${LIBNL_INCLUDE_DIRS} ${NFT_INCLUDE_DIRS})
target_link_libraries(ServerCore PRIVATE ${LIBNL_LIBRARIES} ${NFT_LIBRARIES})

install(TARGETS ServerCore RUNTIME DESTINATION bin LIBRARY DESTINATION bin)
