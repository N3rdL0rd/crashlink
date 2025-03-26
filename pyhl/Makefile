CC = gcc
CFLAGS = -shared -fPIC
PYTHON_INCLUDE = /usr/include/python3.13
PYTHON_LIB = -lpython3.13
HASHLINK_INCLUDE = hashlink/src
INCLUDES = -I$(PYTHON_INCLUDE) -I$(HASHLINK_INCLUDE)

TARGET = pyhl.hdll

all: $(TARGET)

$(TARGET): pyhl.c
	$(CC) $(CFLAGS) -o $@ $< $(INCLUDES) $(PYTHON_LIB)

clean:
	rm -f $(TARGET)

.PHONY: all clean