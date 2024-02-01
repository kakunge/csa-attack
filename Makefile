LDLIBS=-lpcap

all: csa-attack

main.o: main.cpp

radiotap.o: radiotap.h radiotap.cpp

csa-attack: main.o radiotap.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f csa-attack *.o