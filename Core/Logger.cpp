// Logger.cpp — файл + консоль, async sinks, ротация, детерминированный shutdown.

#include "Logger.hpp"

#include <iostream>
#include <filesystem>
#include <memory>

#include <boost/core/null_deleter.hpp>
#include <boost/make_shared.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/attributes/clock.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sinks/async_frontend.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>

namespace
{
    namespace logging  = boost::log;
    namespace sinks    = boost::log::sinks;
    namespace expr     = boost::log::expressions;
    namespace trivial  = boost::log::trivial;
    namespace keywords = boost::log::keywords;

    using file_sink_t = sinks::asynchronous_sink<sinks::text_file_backend>;
    using cout_sink_t = sinks::asynchronous_sink<sinks::text_ostream_backend>;

    /// @brief Форматтер: "TS [level] message". Тэг добавляется макросом в начало message.
    static logging::formatter MakeFormatter()
    {
        return expr::stream
            << expr::format_date_time<boost::posix_time::ptime>("TimeStamp",
                                                                "%Y-%m-%d %H:%M:%S.%f")
            << " [" << trivial::severity << "] "
            << expr::smessage;
    }

    /// @brief Глобальные атрибуты (время).
    static void AddCommonAttrs()
    {
        auto core = logging::core::get();
        core->add_global_attribute("TimeStamp", boost::log::attributes::local_clock());
    }

    /// @brief Создать каталог, если его нет (без выброса исключений).
    static void EnsureDir(const std::string &dir)
    {
        try
        {
            if (!dir.empty())
            {
                std::filesystem::create_directories(dir);
            }
        }
        catch (...)
        {
            // Если каталог создать не удалось — backend сам упадёт при открытии файла.
        }
    }

    // Живут, пока существует Guard.
    boost::shared_ptr<file_sink_t> g_file_sink;
    boost::shared_ptr<cout_sink_t> g_cout_sink;
}

namespace Logger
{
    Guard::Guard(const Options &opts)
    {
        AddCommonAttrs();
        auto core = boost::log::core::get();

        if (opts.enable_file)
        {
            EnsureDir(opts.directory);

            auto backend = boost::make_shared<sinks::text_file_backend>(
                keywords::file_name      = opts.directory + "/" + opts.base_filename + "_%Y-%m-%d_%H-%M-%S.%N.log",
                keywords::rotation_size  = opts.rotation_size_bytes,
                keywords::open_mode      = std::ios_base::app
            );

            backend->set_file_collector(sinks::file::make_collector(
                keywords::target         = opts.directory,
                keywords::max_size       = opts.max_total_size_bytes,
                keywords::min_free_space = opts.min_free_space_bytes
            ));
            backend->scan_for_files();
            backend->auto_flush(true); // безопаснее для продакшна

            g_file_sink = boost::make_shared<file_sink_t>(backend);
            g_file_sink->set_formatter(MakeFormatter());
            g_file_sink->set_filter(trivial::severity >= opts.file_min_severity);
            core->add_sink(g_file_sink);
        }

        if (opts.enable_console)
        {
            auto backend = boost::make_shared<sinks::text_ostream_backend>();
            auto stream  = boost::shared_ptr<std::ostream>(&std::clog, boost::null_deleter());
            backend->add_stream(stream);
            backend->auto_flush(true);

            g_cout_sink = boost::make_shared<cout_sink_t>(backend);
            g_cout_sink->set_formatter(MakeFormatter());
            g_cout_sink->set_filter(trivial::severity >= opts.console_min_severity);
            core->add_sink(g_cout_sink);
        }
    }

    Guard::~Guard()
    {
        auto core = boost::log::core::get();

        // 1) Слить очереди.
        if (g_file_sink)
        {
            g_file_sink->flush();
        }
        core->flush();

        // 2) Снять sinks.
        if (g_cout_sink)
        {
            core->remove_sink(g_cout_sink);
            g_cout_sink.reset();
        }
        if (g_file_sink)
        {
            g_file_sink->stop();
            g_file_sink->flush();
            core->remove_sink(g_file_sink);
            g_file_sink.reset();
        }

        // 3) Финальный flush ядра.
        core->flush();
    }

    void FlushAll()
    {
        if (g_file_sink)
        {
            g_file_sink->flush();
        }
        boost::log::core::get()->flush();
    }
}
