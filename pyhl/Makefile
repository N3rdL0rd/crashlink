CC = gcc
CFLAGS = -shared -fPIC
PYTHON_INCLUDE = ./include
HASHLINK_INCLUDE = hashlink/src
INCLUDES = -I$(PYTHON_INCLUDE) -I$(HASHLINK_INCLUDE)
LIBPYTHON = ./libpython.a

TARGET = pyhl.hdll

all: $(TARGET)

$(TARGET): pyhl.c
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES) $(LIBPYTHON)

clean:
	rm -f $(TARGET)

.PHONY: all clean