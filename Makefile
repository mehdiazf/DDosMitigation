CXX = g++-7 

OBJ = ./obj
Filter = Filter
PROGS = $(Filter) Supervisor
CLEANFILES = $(PROGS) *.o
RM = rm -rf
LDFLAGS = -L /usr/local/lib -lboost_system -pthread -lboost_thread -lboost_chrono -lboost_program_options -ldl -lsqlite3 -levent
CPPFLAGS = -std=c++17 -Wall
MAKE = make
FILTER_DIR = filter

OBJECTS = $(patsubst $(FILTER_DIR)/%.cpp, $(OBJ)/%.o, $(wildcard $(FILTER_DIR)/*.cpp))
SOURCE  = $(wildcard $(FILTER_DIR)/%.cpp)

all: $(PROGS)
$(Filter): $(MAKE)

$(MAKE): $(SOURCE)  $(FILTER_DIR)/Makefile | $(OBJ)
	+$(MAKE) -C $(FILTER_DIR)

$(OBJ):
	+mkdir $(OBJ)

Supervisor: $(OBJ)/sqlite.o $(OBJ)/functions.o $(OBJ)/exceptions.o $(OBJ)/bgp.o $(OBJ)/client.o  main.o
	$(CXX) $(CPPFLAGS) $^ -o $@ $(LDFLAGS)

main.o: broker.cpp
	$(CXX) $(CPPFLAGS) -c broker.cpp -o main.o $(LDFLAGS)

clean:
	@$(RM) $(CLEANFILES)
	@cd $(OBJ) && $(RM) $(CLEANFILES)
	@cd filter && $(MAKE) clean

