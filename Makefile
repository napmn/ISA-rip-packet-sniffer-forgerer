FLAGS = -std=c++11 -lpcap

all: myripsniffer myripresponse

myripsniffer: myripsniffer.cpp myripsniffer.hpp
	g++ myripsniffer.cpp $(FLAGS) -o myripsniffer

myripresponse: myripresponse.cpp myripresponse.hpp
	g++ myripresponse.cpp -std=c++11 -o myripresponse
