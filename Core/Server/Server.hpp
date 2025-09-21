#pragma once

// ===== C ABI exports for shared library mode (argv + len) =====
#include <cstdint>

#define EXPORT extern "C" __attribute__((visibility("default")))

// Запуск клиента в отдельном потоке.
// cfg - json-данные конфига
EXPORT int32_t Start(char *cfg);

// Мягкая остановка: сигналим рабочему коду и НЕ блокируем вызывающего.
EXPORT int32_t Stop(void);

// Статус работы: 1 — запущен, 0 — остановлен
EXPORT int32_t IsRunning(void);
