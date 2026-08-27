ifeq ($(filter $(OS),linux macos win64),)
  $(error Error: OS must be linux, macos, or win64)
endif

SOURCE = $(filter-out navajoPrecompiler.cc,$(wildcard *.cc))
SOURCE += $(wildcard MPFDParser/*.cc)
OBJECTS = $(SOURCE:.cc=.o)

CXXFLAGS += -Wall -Wextra
CXXFLAGS += -I ../include/
CXXFLAGS += -I /opt/intmain/dev/$(OS)/usr/include/

# CXXFLAGS += -DLIBNAVAJO_SOFTWARE_VERSION="1.6.0"

all: ../lib/libnavajo.a ../bin/navajoPrecompiler

../lib/libnavajo.a: $(OBJECTS)
	ar rcs $@ $^

../bin/navajoPrecompiler: navajoPrecompiler.cc
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f *o
	rm -f MPFDParser/*.o
	rm -f ../lib/*.a
	rm -f ../bin/navajoPrecompiler

