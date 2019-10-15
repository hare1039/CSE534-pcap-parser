LDFLAGS=-L/usr/local/opt/libpcap/lib
CPPFLAGS=-I/usr/local/opt/libpcap/include -I.. -std=c++17 -Wall -O3
LIBS=-lpcap

all: analysis_pcap_tcp

analysis_pcap_tcp: analysis_pcap_tcp.cpp ../def.hpp
	$(CXX) $(CPPFLAGS) $(LDFLAGS) -o $@ analysis_pcap_tcp.cpp $(LIBS)

clean:
	rm analysis_pcap_tcp
