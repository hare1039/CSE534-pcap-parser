LDFLAGS=-L/usr/local/opt/libpcap/lib
CPPFLAGS=-I/usr/local/opt/libpcap/include -I.. -std=c++17 -Wall -O3
LIBS=-lpcap

all: analysis_pcap_http

analysis_pcap_http: analysis_pcap_http.cpp ../def.hpp
	$(CXX) $(CPPFLAGS) $(LDFLAGS) -o $@ analysis_pcap_http.cpp $(LIBS)
