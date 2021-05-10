CXX = g++-7

PROGS = ../Filter
CLEANFILES = $(PROGS) *.o
RM = rm -rf
OBJ = ../obj

LDFLAGS = -L /usr/local/lib -lboost_system -pthread  -lboost_thread  -lboost_program_options -lboost_chrono -lip4tc -ldl -lsqlite3
CPPFLAGS = -std=c++17 -Wall

all: $(PROGS)
../Filter: $(OBJ)/anomaly.o $(OBJ)/bgp.o $(OBJ)/ip.o $(OBJ)/parser.o $(OBJ)/functions.o $(OBJ)/afsniff.o $(OBJ)/exceptions.o $(OBJ)/monitor.o $(OBJ)/iptable.o $(OBJ)/sqlite.o $(OBJ)/client.o $(OBJ)/filter.o 
		$(CXX) $(CPPFLAGS) $^ -o $@ $(LDFLAGS)

$(OBJ)/exceptions.o: exceptions.cpp
	$(CXX) $(CPPFLAGS) -c exceptions.cpp -o $(OBJ)/exceptions.o $(LDFLAGS)

$(OBJ)/anomaly.o: anomaly.cpp
	$(CXX) $(CPPFLAGS) -c anomaly.cpp -o $(OBJ)/anomaly.o $(LDFLAGS)

$(OBJ)/ip.o: ip.cpp
	$(CXX) $(CPPFLAGS) -c ip.cpp -o $(OBJ)/ip.o $(LDFLAGS)

$(OBJ)/parser.o: parser.cpp
	$(CXX) $(CPPFLAGS) -c parser.cpp -o $(OBJ)/parser.o $(LDFLAGS)

$(OBJ)/functions.o: functions.cpp
	$(CXX) $(CPPFLAGS) -c functions.cpp -o $(OBJ)/functions.o $(LDFLAGS)

$(OBJ)/afsniff.o: afsniff.cpp
	$(CXX) $(CPPFLAGS) -c afsniff.cpp -o $(OBJ)/afsniff.o $(LDFLAGS)

$(OBJ)/monitor.o: monitor.cpp
	$(CXX) $(CPPFLAGS) -c monitor.cpp -o $(OBJ)/monitor.o $(LDFLAGS)

$(OBJ)/iptable.o: iptable.cpp
	$(CXX) $(CPPFLAGS) -c iptable.cpp -o $(OBJ)/iptable.o $(LDFLAGS) -fpermissive

$(OBJ)/sqlite.o: sqlite.cpp
	$(CXX) $(CPPFLAGS) -c sqlite.cpp -o $(OBJ)/sqlite.o $(LDFLAGS)

$(OBJ)/client.o: client.cpp
	$(CXX) $(CPPFLAGS) -c client.cpp -o $(OBJ)/client.o $(LDFLAGS)

$(OBJ)/bgp.o: bgp.cpp
	$(CXX) $(CPPFLAGS) -c bgp.cpp -o $(OBJ)/bgp.o $(LDFLAGS)

$(OBJ)/filter.o: filter.cpp
	$(CXX) $(CPPFLAGS) -c filter.cpp -o $(OBJ)/filter.o $(LDFLAGS) -fpermissive

clean:
	@$(RM) $(CLEANFILES)

