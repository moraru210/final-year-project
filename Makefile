.PHONY: status start clean

start:
	cd kernel && \
	make && \
	bash ./setup.sh load $(TARGET) && \
	cd ../userspace/lb && \
	go build && \
	./lb 2 2

clean:
	cd kernel && \
	bash ./setup.sh unload $(TARGET) && \
	rm -rf /sys/fs/bpf/$(TARGET)

status:
	cd kernel && \
	bash ./setup.sh status
