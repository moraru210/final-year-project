.PHONY: status start clean

start:
	cd kernel && \
	make MAX_CLIENTS=$(MAX_CLIENTS) MAX_SERVERS=$(MAX_SERVERS) MAX_PER_SERVER=$(MAX_PER_SERVER) && \
	bash ./setup.sh load $(TARGET) && \
	cd ../userspace/lb && \
	rm -f structs.go && \
	cd ../config && \
	go run generate.go $(MAX_CLIENTS) $(MAX_SERVERS) $(MAX_PER_SERVER) && \
	cd ../lb && \
	go build && \
	./lb $(IPv4) $(TARGET)

clean:
	cd kernel && \
	make clean && \
	bash ./setup.sh unload $(TARGET) && \
	rm -rf /sys/fs/bpf/$(TARGET)

status:
	cd kernel && \
	bash ./setup.sh status
