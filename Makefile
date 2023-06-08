.PHONY: status start clean

start:
	cd kernel && \
	make MAX_CLIENTS=$(MAX_CLIENTS) MAX_SERVERS=$(MAX_SERVERS) && \
	bash ./setup.sh load $(TARGET) && \
	cd ../userspace/lb && \
	rm -f structs.go && \
	cd ../config && \
	go run generate.go $(MAX_CLIENTS) $(MAX_SERVERS) && \
	cd ../lb && \
	go build && \
	./lb 2

clean:
	cd kernel && \
	make clean && \
	bash ./setup.sh unload $(TARGET) && \
	rm -rf /sys/fs/bpf/$(TARGET)

status:
	cd kernel && \
	bash ./setup.sh status
