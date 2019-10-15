#include <iostream>
#include <array>
#include <vector>
#include <bitset>
#include <unordered_map>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <cctype>
#include <string_view>

#include <pcap.h>

#include "def.hpp"

struct ethernet_frame
{
    constexpr static int mac_size = 6;
    std::array<std::uint8_t, mac_size> dst_;
    std::array<std::uint8_t, mac_size> src_;
    std::uint16_t type_;

    template<typename Iterator>
    ethernet_frame(Iterator & it)
    {
        readnet(it, dst_);
        readnet(it, src_);
        readnet(it, type_);
    }
};

struct ip_datagram
{
    std::uint8_t  ver_ihl_;
    std::uint8_t  type_;
    std::uint16_t length_;
    std::uint16_t id_;
    std::uint16_t flag_frag_;
    std::uint8_t  TTL_;
    std::uint8_t  protocol_;
    std::uint16_t checksum_;
    std::uint32_t src_;
    std::uint32_t dst_;
    std::uint32_t options_;

    template<typename Iterator>
    ip_datagram(Iterator & it)
    {
        readnet(it, ver_ihl_);
        readnet(it, type_);
        readnet(it, length_);
        readnet(it, id_);
        readnet(it, flag_frag_);
        readnet(it, TTL_);
        readnet(it, protocol_);
        readnet(it, checksum_);
        readnet(it, src_);
        readnet(it, dst_);
    }
};

struct tcp_segment
{
    struct option
    {
        // https://tools.ietf.org/html/rfc1323
        enum class kind : std::uint8_t { end = 0, nop = 1, mss = 2, wss = 3 };
        kind         kind_   = kind::end;
        std::uint8_t length_ = 0;
        std::vector<std::uint8_t> data_;

        template<typename Iterator>
        option(Iterator & it)
        {
            readnet(it, kind_);

            switch(kind_)
            {
            case kind::end:
            case kind::nop:
                break;

            default:
                break;
            }
        }
    };

    std::uint16_t src_port_;
    std::uint16_t dst_port_;
    std::uint32_t seq_;
    std::uint32_t ack_;
    std::uint8_t  data_off_; // special
    std::uint8_t  control_;  // special
    std::uint16_t window_;
    std::uint16_t checksum_;
    std::uint16_t urg_ptr_;
    std::vector<option> options_;
    std::vector<std::uint8_t> payload_;

    template<typename Iterator>
    tcp_segment(Iterator & it)
    {
        Iterator start = it;
        readnet(it, src_port_);
        readnet(it, dst_port_);
        readnet(it, seq_);
        readnet(it, ack_);
        readnet(it, data_off_); data_off_ >>= (4 - 2); // shift 4; * 4; (32 bit words -> 4 bytes)
        readnet(it, control_);
        readnet(it, window_);
        readnet(it, checksum_);
        readnet(it, urg_ptr_);

        for(;;)
        {
            options_.emplace_back(it);
            if (options_.back().kind_ == option::kind::end)
                break;
        }

        it = std::next(start, data_off_);
    }

    template<typename Iterator>
    void read_payload(Iterator it, Iterator end)
    {
        std::copy(it, end, std::back_inserter(payload_));
    }

    enum class tcp_control
    {
        FIN = 0,
        SYN = 1,
        RST = 2,
        PSH = 3,
        ACK = 4,
        URG = 5,
    };

    inline
    bool has_flag(tcp_control ctrl) const
    {
        return control_ & (1 << +ctrl);
    }

    inline
    auto options_at(option::kind k) const -> std::vector<option>::const_iterator
    {
        return std::find_if(options_.begin(),
                            options_.end(),
                            [&k] (option const& o) { return o.kind_ == k; });
    }

    inline
    bool options_contains(option::kind k) const
    {
        return options_at(k) != options_.end();
    }
};

struct tcp_packet
{
    pcap_pkthdr    pcap_header_;
    ethernet_frame ethernet_frame_;
    ip_datagram    ip_datagram_;
    tcp_segment    tcp_segment_;

    template<typename Iterator>
    tcp_packet(pcap_pkthdr &header, Iterator & it, Iterator start):
        pcap_header_   {header},
        ethernet_frame_{it},
        ip_datagram_   {it},
        tcp_segment_   {it}
        {
            tcp_segment_.read_payload(it, std::next(it, pcap_header_.len - std::distance(start, it)));
        }

    template<typename Iterator>
    tcp_packet(pcap_pkthdr &header, Iterator & it): tcp_packet {header, it, it} {}
    tcp_packet(tcp_packet const & pkt) = default;

    bool is_strict_equal (tcp_packet const & pkt) const
    {
        return (ip_datagram_.src_      == pkt.ip_datagram_.src_) and
               (ip_datagram_.dst_      == pkt.ip_datagram_.dst_) and
               (tcp_segment_.src_port_ == pkt.tcp_segment_.src_port_) and
               (tcp_segment_.dst_port_ == pkt.tcp_segment_.dst_port_);
    }

    bool operator == (tcp_packet const & pkt) const
    {
        return packet_hash(*this) == packet_hash(pkt);
    }

    inline static
    auto packet_hash(tcp_packet const& pkt) -> std::size_t
    {
        return (0xFFFF & pkt.ip_datagram_.src_) * pkt.tcp_segment_.src_port_ +
               (0xFFFF & pkt.ip_datagram_.dst_) * pkt.tcp_segment_.dst_port_ ;
    }
};

auto operator << (std::ostream& os, tcp_packet const & pkt) -> std::ostream&
{
    os << "[" << std::setw(2) << pkt.pcap_header_.ts.tv_sec << "." << std::setw(3) << pkt.pcap_header_.ts.tv_usec << "] ";
    os << ip_to_string(pkt.ip_datagram_.src_) << ":" << pkt.tcp_segment_.src_port_ << " -> "
       << ip_to_string(pkt.ip_datagram_.dst_) << ":" << pkt.tcp_segment_.dst_port_ << "; "
       << "SEQ:"   << std::setw(10) << pkt.tcp_segment_.seq_
       << "; ACK:" << std::setw(10) << pkt.tcp_segment_.ack_
       << "; WND:" << std::setw(6)  << pkt.tcp_segment_.window_ << "; ";
    if (pkt.tcp_segment_.has_flag(tcp_segment::tcp_control::FIN))
        os << "FIN; ";
    if (pkt.tcp_segment_.has_flag(tcp_segment::tcp_control::SYN))
        os << "SYN; ";
    if (pkt.tcp_segment_.has_flag(tcp_segment::tcp_control::RST))
        os << "RST; ";
    if (pkt.tcp_segment_.has_flag(tcp_segment::tcp_control::PSH))
        os << "PSH; ";
    if (pkt.tcp_segment_.has_flag(tcp_segment::tcp_control::ACK))
        os << "ACK; ";
    if (pkt.tcp_segment_.has_flag(tcp_segment::tcp_control::URG))
        os << "URG; ";

    if (false /* debug */ and not pkt.tcp_segment_.payload_.empty())
    {
        os << "\n  ";
        for (std::uint8_t c : pkt.tcp_segment_.payload_)
            if (std::isprint(c) or c == '\n')
                std::cout << c;
    }

    return os;
}

class question_3
{
public:
    std::unordered_map<std::size_t, std::vector<tcp_packet>> flow_;

    void operator() (tcp_packet const & pkt)
    {
        std::size_t hashed = tcp_packet::packet_hash(pkt);
        if (flow_.find(hashed) == flow_.end())
            flow_.emplace(hashed, std::vector<tcp_packet>{pkt});
        else
            flow_.at(hashed).push_back(pkt);
    }

    void answer()
    {
        for (auto && pair: flow_)
        {
            std::cout << "[flow #" << pair.first << "]\n";
            a(pair.second);
            std::cout << "\n";
        }
    }

    template<typename Iterator> static
    bool is_http_request(Iterator it)
    {
        std::string v;
        std::copy_n(it, 3, std::back_inserter(v));
        return v == "GET" or v == "POS"; // ...
    }

    void a(std::vector<tcp_packet> const & flow)
    {
        std::uint32_t ack = 0;
        bool response_showed = false;
        for (auto it = flow.begin(); it != flow.end(); ++it)
            if (ip_to_string(it->ip_datagram_.dst_) == "34.193.77.105" and
                it->tcp_segment_.payload_.size() >= 3 and
                is_http_request(it->tcp_segment_.payload_.begin()))
            {
                ack = it->tcp_segment_.ack_;
                response_showed = false;
                std::cout << "  REQUEST:  " << *it << "\n";
            }
            else if (not response_showed and
                     it->tcp_segment_.seq_ == ack and
                     ip_to_string(it->ip_datagram_.src_) == "34.193.77.105" and
                     not it->tcp_segment_.payload_.empty())
            {
                std::cout << "  RESPONSE: " << *it << "\n";
                response_showed = true;
            }

    }
};

int number_of_flows(std::string_view path)
{
    uptr_pcap_t type {perform(pcap_open_offline, path.data())};
    question_3 q3_1;
    for(pcap_pkthdr header;;)
    {
        unsigned char const * packet = pcap_next(type.get(), &header);
        if (!packet)
            break;

        tcp_packet pkt {header, packet};
        q3_1(pkt);
    }
    return q3_1.flow_.size();
}

void load_time(std::string_view path)
{
    uptr_pcap_t type {perform(pcap_open_offline, path.data())};
    std::vector<tcp_packet> list;
    for(pcap_pkthdr header;;)
    {
        unsigned char const * packet = pcap_next(type.get(), &header);
        if (!packet)
            break;

        list.emplace_back(header, packet);
    }
    auto v = to_chrono(list.back().pcap_header_.ts) - to_chrono(list.front().pcap_header_.ts);
    std::cout << std::chrono::duration_cast<std::chrono::milliseconds>(v).count() << " ms\n";
}

int number_of_packets(std::string_view path)
{
    uptr_pcap_t type {perform(pcap_open_offline, path.data())};
    std::vector<tcp_packet> list;
    for(pcap_pkthdr header;;)
    {
        unsigned char const * packet = pcap_next(type.get(), &header);
        if (!packet)
            break;

        list.emplace_back(header, packet);
    }
    return list.size();
}

int total_size(std::string_view path)
{
    uptr_pcap_t type {perform(pcap_open_offline, path.data())};
    int size = 0;
    for(pcap_pkthdr header;;)
    {
        unsigned char const * packet = pcap_next(type.get(), &header);
        if (!packet)
            break;

        tcp_packet pkt {header, packet};
        size += pkt.pcap_header_.len;
    }
    return size;
}

int main(int argc, char *argv[])
{
//    try
//    {
        uptr_pcap_t handle {perform(pcap_open_offline, "./http_1080.pcap")};

        question_3 q3;
        for(pcap_pkthdr header;;)
        {
            unsigned char const * packet = pcap_next(handle.get(), &header);
            if (!packet)
                break;

            tcp_packet pkt {header, packet};
            q3(pkt);
        }
        q3.answer();

        std::cout << "[Q2]\n";
        std::cout << "  http_1080.pcap: " << number_of_flows("http_1080.pcap") << " flows\n";
        std::cout << "  tcp_1081.pcap:  " << number_of_flows("tcp_1081.pcap") << " flows\n";
        std::cout << "  tcp_1082.pcap:  " << number_of_flows("tcp_1082.pcap") << " flows\n\n";

        std::cout << "[Q3]\n";
        std::cout << "  http_1080.pcap: "; load_time("http_1080.pcap");
        std::cout << "  tcp_1081.pcap:  "; load_time("tcp_1081.pcap");
        std::cout << "  tcp_1082.pcap:  "; load_time("tcp_1082.pcap");

        std::cout << "  http_1080.pcap: " << number_of_packets("http_1080.pcap") << " packets\n";
        std::cout << "  tcp_1081.pcap:  " << number_of_packets("tcp_1081.pcap") << " packets\n";
        std::cout << "  tcp_1082.pcap:  " << number_of_packets("tcp_1082.pcap") << " packets\n";

        std::cout << "  http_1080.pcap: " << total_size("http_1080.pcap") << " bytes\n";
        std::cout << "  tcp_1081.pcap:  " << total_size("tcp_1081.pcap") << " bytes\n";
        std::cout << "  tcp_1082.pcap:  " << total_size("tcp_1082.pcap") << " bytes\n";

//    }
//    catch (std::exception &e)
//    {
//        std::cerr << "exception throwed: " << e.what() << "\n";
//    }
}
