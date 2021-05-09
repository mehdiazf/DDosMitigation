CXX = g++-7 

OBJ = obj
Filter = Filter
PROGS = Supervisor
CLEANFILES = $(PROGS) *.o
RM = rm -rf
LDFLAGS = -L /usr/local/lib -lboost_system -lboost_program_options -ldl -lsqlite3 -levent
CPPFLAGS = -std=c++17 -Wall
MAKE = make

all: $(Filter) $(PROGS)

Filter:
	cd filter && $(MAKE)

Supervisor: $(OBJ)/sqlite.o $(OBJ)/functions.o $(OBJ)/exceptions.o main.o
	$(CXX) $(CPPFLAGS) $^ -o $@ $(LDFLAGS)

main.o: broker.cpp
	$(CXX) $(CPPFLAGS) -c broker.cpp -o main.o $(LDFLAGS)

clean:
	$(RM) $(CLEANFILES)
	cd $(OBJ) && $(RM) $(CLEANFILES)
	cd filter && $(MAKE) clean

