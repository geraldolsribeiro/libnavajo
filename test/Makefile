ifeq ($(filter $(OS),linux macos win64),)
  $(error Error: OS must be linux, macos, or win64)
endif

# SOURCE = $(filter-out navajoPrecompiler.cc,$(wildcard *.cc))
# SOURCE += $(wildcard MPFDParser/*.cc)
# OBJECTS = $(SOURCE:.cc=.o)

CXXFLAGS += -Wall -Wextra
CXXFLAGS += -I ../include/
CXXFLAGS += -I /opt/intmain/dev/$(OS)/usr/include/

LDFLAGS += -L../lib/
LDLIBS += -lnavajo
LDLIBS += -lz
LDLIBS += -lssl
LDLIBS += -lcrypto

all: example

example: example.cc
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f example
