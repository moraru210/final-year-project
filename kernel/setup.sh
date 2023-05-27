#!/bin/bash

XDP_LOADER_PATH="../xdp-tools/xdp-loader/xdp-loader"

# Check if the first argument was provided
if [ $# -eq 0 ]; then
    echo "No arguments supplied. Please provide 'load', 'unload', or 'status' as the first argument."
    exit 1
fi

# Perform the action based on the argument
case "$1" in
"load")
    # Check if the second argument was provided
    if [ -z "$2" ]; then
        echo "No network interface supplied for load action. Please provide a network interface as the second argument."
        exit 1
    fi
    echo "Loading XDP program on $2..."
    $XDP_LOADER_PATH load -m skb $2 xdp_prog_kern.o --pin-path /sys/fs/bpf/$2 -v -s xdp_tcp
    if [ $? -ne 0 ]; then
        echo "Failed to load XDP program on $2."
        exit 1
    fi
    ;;
"unload")
    # Check if the second argument was provided
    if [ -z "$2" ]; then
        echo "No network interface supplied for unload action. Please provide a network interface as the second argument."
        exit 1
    fi
    echo "Unloading XDP program from $2..."
    $XDP_LOADER_PATH unload -a $2
    if [ $? -ne 0 ]; then
        echo "Failed to unload XDP program from $2."
        exit 1
    fi
    ;;
"status")
    echo "Getting XDP status..."
    $XDP_LOADER_PATH status
    if [ $? -ne 0 ]; then
        echo "Failed to get XDP status."
        exit 1
    fi
    ;;
*)
    echo "Invalid argument. Please provide 'load', 'unload', or 'status' as the first argument."
    exit 1
    ;;
esac
