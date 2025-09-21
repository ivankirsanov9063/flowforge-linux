#pragma once
// Logger.hpp — Boost.Log: файл + консоль, async sinks, ротация.
// Публичный API — в namespace Logger. Макросы — глобально.

#include <string>
#include <cstddef>

#include <boost/log/trivial.hpp>

namespace Logger
{
    /// @brief Уровни важности (trace < debug < info < warning < error < fatal).
    using severity_t = boost::log::trivial::severity_level;

    /**
     * @brief Опции инициализации логирования.
     */
    struct Options
    {
        /// @brief Имя приложения (идентификатор). Не печатается, но может использоваться в будущем.
        std::string app_name = "app";

        /// @brief Каталог для логов (создаётся при необходимости).
        std::string directory = "logs";

        /// @brief Базовое имя файлов лога.
        std::string base_filename = "app";

        /// @brief Включить запись в файл.
        bool enable_file = true;

        /// @brief Включить вывод в консоль (std::clog).
        bool enable_console = true;

        /// @brief Минимальный уровень для файла.
        severity_t file_min_severity = boost::log::trivial::info;

        /// @brief Минимальный уровень для консоли.
        severity_t console_min_severity = boost::log::trivial::warning;

        /// @brief Размер файла для ротации (байты).
        std::size_t rotation_size_bytes = 32ull * 1024 * 1024; // 32 MB

        /// @brief Максимальный суммарный размер логов в каталоге (байты).
        std::size_t max_total_size_bytes = 2ull * 1024 * 1024 * 1024; // 2 GB

        /// @brief Минимально допустимое свободное место на диске (байты).
        std::size_t min_free_space_bytes = 512ull * 1024 * 1024; // 512 MB
    };

    /**
     * @brief RAII-гвард логирования. В конструкторе — init, в деструкторе — flush/stop/remove.
     * @details Создайте один экземпляр на процесс (обычно в начале main()).
     */
    class Guard
    {
    public:
        /// @brief Инициализирует ядро Boost.Log и добавляет sinks по заданным опциям.
        explicit Guard(const Options &opts);

        /// @brief Снимает sinks, завершает асинхронные очереди и принудительно сбрасывает буферы.
        ~Guard();

        Guard(const Guard &) = delete;
        Guard &operator=(const Guard &) = delete;
    };

    /**
     * @brief Принудительный сброс буферов (полезно в аварийных обработчиках).
     */
    void FlushAll();
}

/**
 * @brief Лог одной строкой с тэгом перед сообщением.
 * Пример: LOGI("net") << "Connected";  // => ... [info] [net] Connected
 * @note Тэг добавляется в начало текстового сообщения; форматтер к атрибутам не привязан.
 */
#define LOGT(TAG) BOOST_LOG_TRIVIAL(trace)  << "[" << (TAG) << "] "
#define LOGD(TAG) BOOST_LOG_TRIVIAL(debug)  << "[" << (TAG) << "] "
#define LOGI(TAG) BOOST_LOG_TRIVIAL(info)   << "[" << (TAG) << "] "
#define LOGW(TAG) BOOST_LOG_TRIVIAL(warning)<< "[" << (TAG) << "] "
#define LOGE(TAG) BOOST_LOG_TRIVIAL(error)  << "[" << (TAG) << "] "
#define LOGF(TAG) BOOST_LOG_TRIVIAL(fatal)  << "[" << (TAG) << "] "
