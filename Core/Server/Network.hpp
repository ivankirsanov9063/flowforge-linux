#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <optional>
#include <arpa/inet.h>

/**
 * @file Network.hpp
 * @brief Низкоуровневая конфигурация сетевых параметров (TUN, адреса, nftables).
 */

// Скрываем libnl из заголовка.
struct nl_sock;

namespace NetConfig
{
    /**
     * @brief CIDR-блок IPv4.
     */
    struct CidrV4
    {
        std::uint32_t addr_be; ///< Адрес в big-endian (network byte order).
        std::uint8_t  prefix;  ///< Длина префикса (0–32).
    };

    /**
     * @brief CIDR-блок IPv6.
     */
    struct CidrV6
    {
        std::array<std::uint8_t, 16> addr;  ///< Адрес (16 байт).
        std::uint8_t                 prefix;///< Длина префикса (0–128).
    };

    /**
     * @brief Параметры конфигурации сервера.
     */
    struct Params
    {
        int mtu = 1400; ///< MTU интерфейса.

        /// Адрес шлюза TUN и префикс пула (без peer) для IPv4.
        CidrV4 v4_local{ inet_addr("10.200.0.1"), 24 };

        /// Адрес шлюза TUN и префикс пула для IPv6.
        CidrV6 v6_local{ /* fd00:dead:beef::1/64 */
            { 0xfd,0x00,0xde,0xad,0xbe,0xef,0,0,0,0,0,0,0,0,0,1 }, 64
        };

        std::string nat44_src = "10.200.0.0/22";      ///< Исходный CIDR для NAT44.
        std::string nat66_src = "fd00:dead:beef::/64";///< Исходный CIDR для NAT66.
    };

    /**
     * @brief Записать значение в sysctl-файл.
     * @param path Путь к файлу.
     * @param val Значение.
     * @return true при успехе.
     */
    bool write_sysctl(const char *path,
                      const char *val);

    /**
     * @brief Записать значение в IPv6 sysctl для интерфейса.
     * @param ifname Имя интерфейса.
     * @param key Ключ sysctl.
     * @param val Значение.
     * @return true при успехе.
     */
    bool write_if_sysctl(const std::string &ifname,
                         const char        *key,
                         const char        *val);

    /**
     * @brief Создать и подключить NETLINK_ROUTE сокет.
     * @return Указатель на nl_sock или nullptr при ошибке.
     */
    nl_sock *nl_connect_route();

    /**
     * @brief Поднять интерфейс и установить MTU.
     * @param sk Сокет Netlink.
     * @param ifindex Индекс интерфейса.
     * @param mtu MTU.
     * @return true при успехе.
     */
    bool link_set_up_and_mtu(nl_sock *sk,
                             int      ifindex,
                             int      mtu);

    /**
     * @brief Удалить все IP-адреса с интерфейса.
     * @param sk Сокет Netlink.
     * @param ifindex Индекс интерфейса.
     * @return true при успехе.
     */
    bool addr_flush_all(nl_sock *sk,
                        int      ifindex);

    /**
     * @brief Добавить IPv4 P2P-адрес.
     * @param sk Сокет Netlink.
     * @param ifindex Индекс интерфейса.
     * @param local_be Локальный адрес (big-endian).
     * @param peer_be Адрес peer (big-endian).
     * @param prefix Длина префикса.
     * @return true при успехе или если адрес уже существует.
     */
    bool addr_add_v4_p2p(nl_sock     *sk,
                         int          ifindex,
                         std::uint32_t local_be,
                         std::uint32_t peer_be,
                         std::uint8_t  prefix);

    /**
     * @brief Добавить локальный IPv4-адрес с префиксом (без peer).
     * @param sk Сокет Netlink.
     * @param ifindex Индекс интерфейса.
     * @param local_be Локальный адрес (big-endian).
     * @param prefix Длина префикса.
     * @return true при успехе или если адрес уже существует.
     */
    bool addr_add_v4_local(nl_sock     *sk,
                           int          ifindex,
                           std::uint32_t local_be,
                           std::uint8_t  prefix);

    /**
     * @brief Добавить локальный IPv6-адрес.
     * @param sk Сокет Netlink.
     * @param ifindex Индекс интерфейса.
     * @param local Адрес IPv6.
     * @param prefix Длина префикса.
     * @return true при успехе или если адрес уже существует.
     */
    bool addr_add_v6_local(nl_sock                              *sk,
                           int                                   ifindex,
                           const std::array<std::uint8_t, 16>  &local,
                           std::uint8_t                         prefix);

    /**
     * @brief Разобрать строку IPv4 CIDR.
     * @param s Строка "A.B.C.D/len" (по умолчанию /32).
     * @param out Результат.
     * @return true при успехе.
     */
    bool parse_cidr4(const std::string &s,
                     CidrV4            &out);

    /**
     * @brief Разобрать строку IPv6 CIDR.
     * @param s Строка "xxxx::1/len" (по умолчанию /128).
     * @param out Результат.
     * @return true при успехе.
     */
    bool parse_cidr6(const std::string &s,
                     CidrV6            &out);

    /**
     * @brief Нормализовать к сети "A.B.C.D/p" (обнулить хостовые биты).
     * @param c CIDR IPv4.
     * @return Строка сети.
     */
    std::string to_network_cidr(const CidrV4 &c);

    /**
     * @brief Нормализовать к сети "xxxx::/p" (обнулить хостовые биты).
     * @param c CIDR IPv6.
     * @return Строка сети.
     */
    std::string to_network_cidr(const CidrV6 &c);

    /**
     * @brief Найти имя интерфейса маршрута по умолчанию.
     * @param sk Сокет Netlink.
     * @param family AF_INET или AF_INET6.
     * @return Имя интерфейса или std::nullopt.
     */
    std::optional<std::string> find_default_oifname(nl_sock *sk,
                                                    int      family);

    /**
     * @brief Проверка доступности nftables в рантайме.
     * @return true если команды nftables можно выполнять.
     */
    bool nft_feature_probe();

    /**
     * @brief Выполнить набор команд nftables.
     * @param commands Строка с командами.
     * @return true при успехе или некритичной ошибке.
     */
    bool nft_apply(const std::string &commands);

    /**
     * @brief Настроить NAT44 на интерфейсе.
     * @param oifname Имя интерфейса.
     * @param src_cidr Исходный CIDR.
     * @return true при успехе.
     */
    bool ensure_nat44(const std::string &oifname,
                      const std::string &src_cidr);

    /**
     * @brief Настроить NAT66 на интерфейсе.
     * @param oifname Имя интерфейса.
     * @param src_cidr Исходный CIDR.
     * @return true при успехе.
     */
    bool ensure_nat66(const std::string &oifname,
                      const std::string &src_cidr);

    /**
     * @brief Применить серверную конфигурацию (адресация TUN, форвардинг, NAT/MSS).
     * @param ifname Имя TUN-интерфейса.
     * @param p Параметры конфигурации.
     * @param with_nat_fw Включать NAT/MSS/форвардинг.
     * @throws std::runtime_error при критической ошибке.
     */
    void ApplyServerSide(const std::string &ifname,
                         const Params      &p          = Params{},
                         bool               with_nat_fw = true);
} // namespace NetConfig
