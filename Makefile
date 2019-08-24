LDLIBS = -lnetfilter_queue
TARGET = netfilter_test

all: $(TARGET)

clean:
	rm -f $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) -o $@ $< $(LDLIBS)
