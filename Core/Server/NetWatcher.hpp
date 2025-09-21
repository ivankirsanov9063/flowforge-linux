#pragma once

#include "Network.hpp"

#include <string>
#include <optional>
#include <thread>
#include <atomic>
#include <mutex>

/**
 * @file NetWatcher.hpp
 * @brief Вотчер за изменениями default route с пересборкой NAT/MSS.
 *
 * Отслеживает RTNLGRP_IPV4_ROUTE/RTNLGRP_IPV6_ROUTE, при изменениях
 * переопределяет NAT44/NAT66 и MSS clamp идемпотентно.
 * Ошибки инициализации — std::runtime_error. Деструктор останавливает поток.
 */

// Внешняя зависимость libnl скрыта от заголовка.
struct nl_sock;

class NetWatcher
{
public:
    /**
     * @brief Конструктор: запускает вотчер.
     * @param params Параметры сетевой конфигурации (MTU, CIDR источника NAT и т. п.).
     * @throws std::runtime_error При ошибке инициализации netlink/nftables.
     */
    explicit NetWatcher(const NetConfig::Params &params = NetConfig::Params{});

    /**
     * @brief Деструктор: корректно завершает поток и освобождает ресурсы.
     */
    ~NetWatcher();

    /**
     * @brief Последний известный WAN-интерфейс для IPv4.
     * @return Имя интерфейса или std::nullopt.
     */
    std::optional<std::string> Wan4() const;

    /**
     * @brief Последний известный WAN-интерфейс для IPv6.
     * @return Имя интерфейса или std::nullopt.
     */
    std::optional<std::string> Wan6() const;

private:
    /**
     * @brief Параметры конфигурации (CIDR для NAT, MTU и пр.).
     */
    NetConfig::Params params_;

    /**
     * @brief NETLINK_ROUTE сокет (libnl), владеем ресурсом.
     */
    nl_sock *sk_ = nullptr;

    /**
     * @brief Флаг завершения рабочего потока.
     */
    std::atomic<bool> stop_{false};

    /**
     * @brief Рабочий поток, читающий netlink-события.
     */
    std::thread th_;

    /**
     * @brief Мьютекс для защиты last_wan4_/last_wan6_.
     */
    mutable std::mutex mu_;

    /**
     * @brief Последний обнаруженный WAN-интерфейс для IPv4.
     */
    std::optional<std::string> last_wan4_;

    /**
     * @brief Последний обнаруженный WAN-интерфейс для IPv6.
     */
    std::optional<std::string> last_wan6_;

    /**
     * @brief Точка входа рабочего потока: опрос netlink и реакция.
     */
    void ThreadMain_();

    /**
     * @brief Пересчитать WAN-интерфейсы и применить NAT/MSS при изменении.
     */
    void RecomputeAndApply_();

    /**
     * @brief Идемпотентно применяет NAT и MSS clamp под текущие WAN.
     *        При отсутствии WAN соответствующая цепочка очищается.
     * @param wan4 Имя WAN для IPv4 (или std::nullopt).
     * @param wan6 Имя WAN для IPv6 (или std::nullopt).
     * @param p   Параметры конфигурации (MTU, CIDR источника и пр.).
     */
    static void ApplyNatAndMss_(const std::optional<std::string> &wan4,
                                const std::optional<std::string> &wan6,
                                const NetConfig::Params          &p);
};
