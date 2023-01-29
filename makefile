CC=g++
CFLAGS=-c -Wall -lpcap -std=c++11
LDFLAGS=
SOURCES=index.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=index.exe

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ -lpcap

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS) $(EXECUTABLE)
