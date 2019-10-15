#include <iostream>
#include <array>
#include <vector>
#include <bitset>
#include <unordered_map>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <numeric>

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
            case kind::mss:
            case kind::wss:
                readnet(it, length_);
                data_.resize(length_ - 2 /* remove kind and length */);
                readnet(it, data_);
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
    tcp_packet(pcap_pkthdr &header, Iterator & it):
        pcap_header_   {header},
        ethernet_frame_{it},
        ip_datagram_   {it},
        tcp_segment_   {it} {}

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

    return os;
}

// questions

class question_1
{
public:
    int count = 0;
    void operator() (tcp_packet const & pkt)
    {
        if (ip_to_string(pkt.ip_datagram_.src_) == "130.245.145.12" and
            pkt.tcp_segment_.has_flag(tcp_segment::tcp_control::SYN))
            count++;
    }

    void answer()
    {
        std::cout << "[Q1] " << count << "\n";
    }
};

class question_2
{
public:
    std::unordered_map<std::size_t, std::vector<tcp_packet>> flow_;
    std::unordered_map<std::size_t, std::chrono::system_clock::duration> rtt_;

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
            b(pair.second);
            c(pair.second);
            d(pair.second);
            part_b_1(pair.second);
            part_b_2(pair.second);
        }
    }

    void a(std::vector<tcp_packet> const & flow)
    {
        std::cout << " [question_2_a]\n";

        int window_factor = 1;
        for (auto it = flow.begin(); std::distance(flow.begin(), it) < 13; ++it)
        {
            std::cout << "  " << *it;
            if (window_factor != 1)
                std::cout << "CWD:" << (it->tcp_segment_.window_ << window_factor) << "; ";

            if (it->tcp_segment_.has_flag(tcp_segment::tcp_control::SYN) and
                it->tcp_segment_.options_contains(tcp_segment::option::kind::wss))
                window_factor = it->tcp_segment_.options_at(tcp_segment::option::kind::wss)->data_.front();
            std::cout << "\n";
        }
    }

    void b(std::vector<tcp_packet> const & flow)
    {
        std::cout << " [question_2_b]\n";
        auto start = to_chrono(flow.front().pcap_header_.ts);
        auto end   = to_chrono(flow.back().pcap_header_.ts);
        auto time_elasp = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        int total_bytes = std::accumulate(flow.begin(), flow.end(), 0,
                                          [](int & sum, tcp_packet const & b)
                                              { return sum + b.pcap_header_.len; });

        using quotient = std::ratio_divide<std::chrono::seconds::period, decltype(time_elasp)::period>;
        constexpr double fix = 1 / (quotient::num * 1.0 / quotient::den);
        std::cout << "  " << total_bytes << " bytes\n";
        std::cout << "  " << (time_elasp.count()) << " milliseconds\n";
        std::cout << "  " << std::fixed << total_bytes / (time_elasp.count() * fix) << " bytes/s \n";
    }

    void c(std::vector<tcp_packet> const & flow)
    {
        std::cout << " [question_2_d]\n";

        int count = 0;
        std::unordered_map<std::uint32_t, int> seq_counter;
        for (tcp_packet const &pkt : flow)
            if (ip_to_string(pkt.ip_datagram_.src_) == "130.245.145.12")
                count++, seq_counter[pkt.tcp_segment_.seq_]++;

        int loss = 0;
        for (auto && pair : seq_counter)
            loss += pair.second - 1;

        std::cout << "  " << loss << " lost\n";
        std::cout << "  " << count << " total\n";
        std::cout << "  " << loss * 1.0 / count << " % lost\n";
    }

    void d(std::vector<tcp_packet> const & flow)
    {
        std::cout << " [question_2_d]\n";

        std::unordered_map<std::uint32_t, std::chrono::system_clock::time_point> start_pt;
        std::chrono::system_clock::duration rtt {std::chrono::seconds{0}};
        int count = 0;
        for (tcp_packet const &pkt : flow)
        {
            if (ip_to_string(pkt.ip_datagram_.src_) == "130.245.145.12")
                start_pt[pkt.tcp_segment_.seq_] = to_chrono(pkt.pcap_header_.ts);

            if (ip_to_string(pkt.ip_datagram_.dst_) == "130.245.145.12")
            {
                if (start_pt.empty())
                    break;

                for (std::uint32_t s = pkt.tcp_segment_.ack_; ;s--)
                    if (auto it = start_pt.find(s); it != start_pt.end())
                    {
                        rtt += (to_chrono(pkt.pcap_header_.ts) - it->second);
                        count++;
                        break;
                    }
            }
        }
        std::cout << "  " << count << " count\n";
        std::cout << "  " << std::chrono::duration_cast<std::chrono::milliseconds>(rtt).count() * 1.0 / count << " ms\n";

        std::size_t hashed = tcp_packet::packet_hash(flow.front());
        rtt_[hashed] = rtt / count;
    }

    void part_b_1(std::vector<tcp_packet> const & flow)
    {
        std::cout << " [part B question_1]\n";
        auto rtt = rtt_[tcp_packet::packet_hash(flow.front())];
        int showed = 0, size = 0;

        auto current = to_chrono(flow.front().pcap_header_.ts);
        for (tcp_packet const &pkt : flow)
            if (ip_to_string(pkt.ip_datagram_.src_) == "130.245.145.12")
            {
                auto packet_time = to_chrono(pkt.pcap_header_.ts);
                if (current + rtt > packet_time)
                    size += pkt.pcap_header_.len;
                else
                {
                    std::cout << "  size: " << size << "\n";
                    size = 0;
                    current = packet_time;
                    if (showed++ > 11)
                        break;
                }
            }
    }

    void part_b_2(std::vector<tcp_packet> const & flow)
    {
        std::cout << " [part_b_2]\n";
        std::uint32_t prev_ack = 0, prev_ack_count = 0, retransmit = 0;

        for (tcp_packet const &pkt : flow)
            if (pkt.tcp_segment_.has_flag(tcp_segment::tcp_control::ACK) and
                ip_to_string(pkt.ip_datagram_.dst_) == "130.245.145.12")
            {
                if (pkt.tcp_segment_.ack_ == prev_ack)
                    prev_ack_count++;
                else
                {
                    prev_ack = pkt.tcp_segment_.ack_;
                    prev_ack_count = 0;
                }

                if (prev_ack_count > 3)
                {
                    retransmit++;
                    prev_ack_count = 0;
                }
            }
        std::cout << "  " << retransmit << " retransmits\n";
    }

};

int main(int argc, char *argv[])
{
    try
    {
        uptr_pcap_t handle {perform(pcap_open_offline, "./assignment2.pcap")};

        question_1 q1;
        question_2 q2;
        for(pcap_pkthdr header;;)
        {
            unsigned char const * packet = pcap_next(handle.get(), &header);
            if (!packet)
                break;

            tcp_packet pkt {header, packet};
            q1(pkt);
            q2(pkt);
        }

        q1.answer();
        q2.answer();
    }
    catch (std::exception &e)
    {
        std::cerr << "exception thrown: " << e.what() << "\n";
    }
}
