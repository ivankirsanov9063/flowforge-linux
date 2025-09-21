#pragma once

#include <string>
#include <optional>
#include <unordered_map>
#include <vector>

/**
 * @file NetworkRollback.hpp
 * @brief RAII-класс отката сетевых правок, вносимых сервером.
 *
 * Делает snapshot ключевых sysctl и наших nft-таблиц и
 * восстанавливает их при разрушении объекта.
 */
class NetworkRollback
{
public:
    /**
     * @brief Создаёт snapshot текущего сетевого состояния.
     *
     * Конструктор ничего не меняет — только сохраняет значения
     * для последующего восстановления.
     */
    NetworkRollback();

    /**
     * @brief Восстанавливает сохранённое состояние (идемпотентно).
     *
     * Никогда не бросает исключений.
     */
    ~NetworkRollback();

    /**
     * @brief Признак успешного snapshot-а.
     * @return true, если удалось сохранить sysctl и nft-ruleset.
     */
    bool Ok() const;

private:
    // --- Сохранённые sysctl ---

    /** @brief net.ipv4.ip_forward. */
    std::optional<std::string> ip_forward_prev_;

    /** @brief net.ipv6.conf.all.forwarding. */
    std::optional<std::string> ip6_forward_prev_;

    /**
     * @brief net.ipv6.conf.<iface>.accept_ra для всех интерфейсов.
     * Ключ — имя интерфейса, значение — строка sysctl.
     */
    std::unordered_map<std::string, std::string> accept_ra_prev_;

    // --- Снимки наших nft-таблиц (могут быть пустыми) ---

    /** @brief Содержимое table ip flowforge_nat. */
    std::string nft_ip_nat_prev_;
    /** @brief Содержимое table ip6 flowforge_nat. */
    std::string nft_ip6_nat_prev_;
    /** @brief Содержимое table inet flowforge_post. */
    std::string nft_inet_post_prev_;
    /** @brief Содержимое table inet flowforge_fw. */
    std::string nft_inet_fw_prev_;

    // --- Baseline sysctl, которые меняет ApplyServerSide ---

    /** @brief net.ipv6.conf.all.accept_ra. */
    std::optional<std::string> ip6_accept_ra_all_prev_;
    /** @brief net.ipv6.conf.default.accept_ra. */
    std::optional<std::string> ip6_accept_ra_def_prev_;

    /** @brief net.ipv4.conf.all.accept_redirects. */
    std::optional<std::string> ip4_acc_redir_all_prev_;
    /** @brief net.ipv4.conf.default.accept_redirects. */
    std::optional<std::string> ip4_acc_redir_def_prev_;
    /** @brief net.ipv4.conf.all.send_redirects. */
    std::optional<std::string> ip4_send_redir_all_prev_;
    /** @brief net.ipv4.conf.default.send_redirects. */
    std::optional<std::string> ip4_send_redir_def_prev_;

    /** @brief net.ipv6.conf.all.accept_redirects. */
    std::optional<std::string> ip6_acc_redir_all_prev_;
    /** @brief net.ipv6.conf.default.accept_redirects. */
    std::optional<std::string> ip6_acc_redir_def_prev_;

    /** @brief net.ipv4.conf.all.accept_local. */
    std::optional<std::string> ip4_accept_local_all_prev_;
    /** @brief net.ipv4.conf.default.accept_local. */
    std::optional<std::string> ip4_accept_local_def_prev_;

    /** @brief Флаг успешного snapshot-а (sysctl + nft). */
    bool ok_ = false;

    /**
     * @brief Прочитать sysctl по dotted-имени.
     * @param dotted Например, "net.ipv4.ip_forward".
     * @return Строковое значение или std::nullopt при ошибке.
     */
    static std::optional<std::string> ReadSysctl(const std::string &dotted);

    /**
     * @brief Записать sysctl по dotted-имени.
     * @param dotted Полное имя.
     * @param value Новое значение.
     * @return true при успехе записи.
     */
    static bool WriteSysctl(const std::string &dotted,
                            const std::string &value);

    /**
     * @brief Перечислить имена интерфейсов из /proc/sys/net/ipv6/conf.
     * @return Вектор имён (lo, eth0, all, default, ...).
     */
    static std::vector<std::string> ListIpv6ConfIfaces();

    /**
     * @brief Выполнить 'list ...' в nft и вернуть вывод.
     * @param list_cmd Команда, например "list table ip flowforge_nat".
     * @return Текст ruleset-а или пустая строка, если объект отсутствует.
     */
    static std::string NftList(const std::string &list_cmd);

    /**
     * @brief Выполнить набор команд nft из буфера.
     * @param script Текст команд.
     * @return true при успешном выполнении (или допустимой ошибке отката).
     */
    static bool NftRun(const std::string &script);

    /**
     * @brief Внутреннее восстановление сохранённого состояния (noexcept).
     */
    void Restore_() noexcept;
};
