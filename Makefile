CXX = g++-7

PROGS = filter
CLEANFILES = $(PROGS) *.o
RM = rm -rf

LDFLAGS = -L /usr/local/lib -lboost_system -pthread  -lboost_thread  -lboost_program_options -lboost_chrono -lip4tc -ldl -lsqlite3
CPPFLAGS = -std=c++17 -Wall

all: $(PROGS)
filter: anomaly.o ip.o parser.o functions.o afsniff.o exceptions.o monitor.o iptable.o sqlite.o main.o 
	$(CXX) $(CPPFLAGS) $^ -o $@ $(LDFLAGS)

exceptions.o: exceptions.cpp
	$(CXX) $(CPPFLAGS) -c exceptions.cpp -o exceptions.o $(LDFLAGS)

anomaly.o: anomaly.cpp
	$(CXX) $(CPPFLAGS) -c anomaly.cpp -o anomaly.o $(LDFLAGS)

ip.o: ip.cpp
	$(CXX) $(CPPFLAGS) -c ip.cpp -o ip.o $(LDFLAGS)

parser.o: parser.cpp
	$(CXX) $(CPPFLAGS) -c parser.cpp -o parser.o $(LDFLAGS)

function.o: function.cpp
	$(CXX) $(CPPFLAGS) -c functions.cpp -o  functions.o $(LDFLAGS)

afsniff.o: afsniff.cpp
	$(CXX) $(CPPFLAGS) -c afsniff.cpp -o afsniff.o $(LDFLAGS)

monitor.o: monitor.cpp
	$(CXX) $(CPPFLAGS) -c monitor.cpp -o monitor.o $(LDFLAGS)

iptable.o: iptable.cpp
	$(CXX) $(CPPFLAGS) -c iptable.cpp -o iptable.o $(LDFLAGS) -fpermissive

sqlite.o: sqlite.cpp
	$(CXX) $(CPPFLAGS) -c sqlite.cpp -o sqlite.o $(LDFLAGS)

main.o: main.cpp
	$(CXX) $(CPPFLAGS) -c main.cpp -o main.o $(LDFLAGS) -fpermissive

clean:
	$(RM) $(CLEANFILES)

