#pragma once

#include <string>
#include <functional>
#include <csignal>
#include <cstdint>
#include <cstddef>
#include <boost/json/object.hpp>

namespace PluginWrapper
{
    /**
     * @brief Тип функции плагина для подключения клиента.
     * @param config Объект JSON.
     * @return true при успешном подключении.
     */
    using Client_Connect_t =
            bool (*)(boost::json::object& config) noexcept;

    /**
     * @brief Тип функции плагина для отключения клиента.
     */
    using Client_Disconnect_t =
            void (*)(void) noexcept;

    /**
     * @brief Тип функции плагина для обработки трафика клиента.
     * @param receive_from_net Функция чтения данных из сети.
     * @param send_to_net Функция отправки данных в сеть.
     * @param working_flag Указатель на флаг продолжения работы.
     * @return Код завершения работы.
     */
    using Client_Serve_t =
            int (*)(const std::function<ssize_t(std::uint8_t *buf,
                                                std::size_t len)> &receive_from_net,
    const std::function<ssize_t(const std::uint8_t *buf,
                                std::size_t len)> &send_to_net,
    const volatile sig_atomic_t *working_flag) noexcept;

    /**
     * @brief Тип функции плагина для привязки сервера к порту.
     * @param config Объект JSON.
     * @return true при успехе.
     */
    using Server_Bind_t =
            bool (*)(boost::json::object& config) noexcept;

    /**
     * @brief Тип функции плагина для обработки трафика сервера.
     * @param receive_from_net Функция чтения данных из сети.
     * @param send_to_net Функция отправки данных в сеть.
     * @param working_flag Указатель на флаг продолжения работы.
     * @return Код завершения работы.
     */
    using Server_Serve_t =
            int (*)(const std::function<ssize_t(std::uint8_t *buf,
                                                std::size_t len)> &receive_from_net,
    const std::function<ssize_t(const std::uint8_t *buf,
                                std::size_t len)> &send_to_net,
    const volatile sig_atomic_t *working_flag) noexcept;

    /**
     * @brief Структура для хранения загруженного плагина и указателей на его функции.
     */
    struct Plugin
    {
        void *             handle            = nullptr; ///< Дескриптор загруженной библиотеки.
        Client_Connect_t    Client_Connect    = nullptr; ///< Указатель на функцию Client_Connect.
        Client_Disconnect_t Client_Disconnect = nullptr; ///< Указатель на функцию Client_Disconnect.
        Client_Serve_t      Client_Serve      = nullptr; ///< Указатель на функцию Client_Serve.
        Server_Bind_t       Server_Bind       = nullptr; ///< Указатель на функцию Server_Bind.
        Server_Serve_t      Server_Serve      = nullptr; ///< Указатель на функцию Server_Serve.

        Plugin() = default;
    };

    /**
     * @brief Получает символ из динамической библиотеки.
     * @param h Дескриптор открытой библиотеки.
     * @param name Имя экспортируемого символа.
     * @return Указатель на символ или nullptr.
     */
    void* Sym(void *h, const char *name);

    /**
     * @brief Загружает плагин и инициализирует его функции.
     * @param path Путь к файлу плагина (.so).
     * @return Структура Plugin с загруженными функциями.
     */
    Plugin Load(const std::string &path);

    /**
     * @brief Выгружает плагин.
     * @param plugin Структура плагина.
     */
    void Unload(const Plugin &plugin);

    /**
     * @brief Вызывает функцию Client_Connect плагина.
     * @param plugin Загруженный плагин.
     * @param config Объект JSON
     * @return true при успешном подключении.
     */
    bool Client_Connect(const Plugin &plugin,
                        boost::json::object& config) noexcept;

    /**
     * @brief Вызывает функцию Client_Disconnect плагина.
     * @param plugin Загруженный плагин.
     */
    void Client_Disconnect(const Plugin &plugin) noexcept;

    /**
     * @brief Вызывает функцию Client_Serve плагина.
     * @param plugin Загруженный плагин.
     * @param receive_from_net Функция чтения данных из сети.
     * @param send_to_net Функция отправки данных в сеть.
     * @param working_flag Указатель на флаг продолжения работы.
     * @return Код завершения работы.
     */
    int Client_Serve(const Plugin &plugin,
                     const std::function<ssize_t(std::uint8_t *buf,
                                                 std::size_t len)> &receive_from_net,
    const std::function<ssize_t(const std::uint8_t *buf,
                                std::size_t len)> &send_to_net,
    const volatile sig_atomic_t *working_flag) noexcept;

    /**
     * @brief Вызывает функцию Server_Bind плагина.
     * @param plugin Загруженный плагин.
     * @param config Объект JSON
     * @return true при успехе.
     */
    bool Server_Bind(const Plugin &plugin, boost::json::object& config) noexcept;

    /**
     * @brief Вызывает функцию Server_Serve плагина.
     * @param plugin Загруженный плагин.
     * @param receive_from_net Функция чтения данных из сети.
     * @param send_to_net Функция отправки данных в сеть.
     * @param working_flag Указатель на флаг продолжения работы.
     * @return Код завершения работы.
     */
    int Server_Serve(const Plugin &plugin,
                     const std::function<ssize_t(std::uint8_t *buf,
                                                 std::size_t len)> &receive_from_net,
    const std::function<ssize_t(const std::uint8_t *buf,
                                std::size_t len)> &send_to_net,
    const volatile sig_atomic_t *working_flag) noexcept;
}
