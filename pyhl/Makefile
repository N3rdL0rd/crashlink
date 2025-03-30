CC = gcc
CFLAGS = -shared -fPIC
PYTHON_INCLUDE = ./include
HASHLINK_INCLUDE = hashlink/src
INCLUDES = -I$(PYTHON_INCLUDE) -I$(HASHLINK_INCLUDE)
LIBPYTHON = ./libpython.a

EXTRA_LIBS = -ldl -lm -lpthread -lutil -lz

TARGET = pyhl.hdll

all: $(TARGET)

$(TARGET): pyhl.c
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES) -Wl,--whole-archive $(LIBPYTHON) -Wl,--no-whole-archive $(EXTRA_LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean