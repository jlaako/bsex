CXX = g++
CXXFLAGS = -mtune=generic -O3 -pthread
CXXFLAGS += `pkg-config --cflags botan-2`
DEFS = -D_LARGEFILE64_SOURCE -D_REENTRANT -D_THREAD_SAFE
INCS =
LDFLAGS = -pthread -O3
LIBS = `pkg-config --libs botan-2`

DESTDIR = /usr/local

SRCS = bsex.cpp

OBJS = bsex.o

default: all

all: bsex

.cpp.o: $(SRCS)
	$(CXX) $(CXXFLAGS) $(DEFS) $(INCS) -c $<

bsex: $(OBJS)
	$(CXX) $(LDFLAGS) -o bsex $(OBJS) $(LIBS)

install: bsex
	strip bsex
	install -m 755 -d $(DESTDIR)/bin
	install -m 755 bsex $(DESTDIR)/bin

clean:
	rm -f *~ *.o core*

distclean:
	rm -f *~ *.o core* bsex Makefile.dep

Makefile.dep: $(SRCS)
	$(CXX) $(DEFS) $(INCS) -MM $(SRCS) >Makefile.dep

include Makefile.dep

