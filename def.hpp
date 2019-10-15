#ifndef DEF_HPP_
#define DEF_HPP_

#include <functional>
#include <memory>
#include <iterator>
#include <cstring>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

struct pcap_deleter { void operator() (pcap_t* p) { pcap_close(p); } };
using uptr_pcap_t = std::unique_ptr<pcap_t, pcap_deleter>;

template<typename Function, typename ... Args>
auto perform(Function&& f, Args&& ... args)
{
    static char errbuf[PCAP_ERRBUF_SIZE];
    if (auto&& result = std::invoke(f, std::forward<Args>(args)..., errbuf))
        return result;
    else
        throw std::runtime_error{errbuf};
}

using ipv4 = std::uint32_t;
auto ip_to_string(ipv4 ip) -> std::string
{
    sockaddr_in a;
    a.sin_addr.s_addr = htonl(ip);
    return inet_ntoa(a.sin_addr);
}

// general ntoh
template<typename IntegerType>
auto ntoh(IntegerType data) -> IntegerType
{
    static_assert(std::is_integral_v<IntegerType>);
    static_assert(sizeof(IntegerType) == sizeof(std::uint8_t) or
                  sizeof(IntegerType) == sizeof(std::uint16_t) or
                  sizeof(IntegerType) == sizeof(std::uint32_t));

    if constexpr (sizeof(IntegerType) == sizeof(std::uint8_t))
        return data;
    else if constexpr (sizeof(IntegerType) == sizeof(std::uint16_t))
        return ntohs(data);
    else
        return ntohl(data);
}

// read 'it' into data and advance sizeof(data)
template<typename Iterator,
         typename IntegerType,
         std::enable_if_t<std::is_integral_v<IntegerType> or
                          std::is_enum_v<IntegerType>, int> = 0>
auto readnet(Iterator & it, IntegerType &data) -> IntegerType
{
    std::memcpy(std::addressof(data), std::addressof(*it), sizeof(IntegerType));
    std::advance(it, sizeof(IntegerType));

    if constexpr (std::is_enum_v<IntegerType>)
        return data = static_cast<IntegerType>(ntoh(static_cast<std::underlying_type_t<IntegerType>>(data)));
    else
        return data = ntoh(data);
}

template <typename, typename = std::void_t<>>
struct has_data_size : std::false_type {};

template <typename T>
struct has_data_size<T,
                     std::void_t<decltype(std::declval<T>().data()),
                                 decltype(std::declval<T>().size())>
                     > : std::true_type {};

template<typename Iterator,
         typename Container,
         std::enable_if_t<has_data_size<Container>::value, int> = 0>
void readnet(Iterator & it, Container & container)
{
    std::memcpy(container.data(), std::addressof(*it), container.size());
    std::advance(it, container.size());
}

template<typename Enum,
         std::enable_if_t<std::is_enum_v<Enum>, int> = 0>
int  operator+(Enum const& e)
{
    return static_cast<std::underlying_type_t<Enum>>(e);
}

auto to_chrono(timeval const & t) -> std::chrono::system_clock::time_point
{
    auto tp = std::chrono::seconds {t.tv_sec} + std::chrono::microseconds {t.tv_usec};
    return std::chrono::system_clock::time_point {} + tp;
}

#endif // DEF_HPP_
