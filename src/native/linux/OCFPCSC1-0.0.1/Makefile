CC        = g++
LD        = ld -export-dynamic
OBJS     := $(patsubst %.cpp,%.o,$(wildcard *.cpp))
JDK_HOME  = /usr/java/j2sdk1.4.2_05
PCSC_HDRS = -I/usr/include
PCSC_LIBS = -L/usr/lib -lpcsclite 
INCLUDE   = -I$(JDK_HOME)/include/linux -I$(JDK_HOME)/include $(PCSC_HDRS)
LIBNAME   = libOCFPCSC1.so

all: $(LIBNAME)

clean:
	rm -f *.so *.o

install:
	cp -f *.so /usr/local/pcsc/lib

$(LIBNAME): $(OBJS)
	$(LD) -Bsymbolic -shared $(OBJS) $(PCSC_LIBS) -lc -lstdc++ -o $@

$(patsubst %.cpp,%.o,$(wildcard *.cpp)) : %.o : %.cpp
	$(CC) $(CFLAGS) -c $< $(INCLUDE) $(DEFS)
