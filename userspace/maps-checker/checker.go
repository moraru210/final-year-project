package main

import (
	"fmt"
	"os"

	bpf "github.com/cilium/cilium/pkg/bpf"
)

const (
	connectionMapPath = "/sys/fs/bpf/lo/conn_map"
	numbersMapPath    = "/sys/fs/bpf/lo/numbers_map"
)

type Connection struct {
	SrcIP   uint32
	DestIP  uint32
	SrcPort uint16
	DestPort uint16
}

type Numbers struct {
	Number1 uint32
	Number2 uint32
}

func main() {
	connMap, err := bpf.LoadMap(connectionMapPath)
	if err != nil {
		fmt.Println("Error finding connection map: ", err.Error())
		os.Exit(1)
	}
	fmt.Println("Connection map:")
	if err := printMap(connMap, &Connection{}); err != nil {
		fmt.Println("Error printing connection map: ", err.Error())
	}

	numbersMap, err := bpf.LoadMap(numbersMapPath)
	if err != nil {
		fmt.Println("Error finding numbers map: ", err.Error())
		os.Exit(1)
	}
	fmt.Println("Numbers map:")
	if err := printMap(numbersMap, &Numbers{}); err != nil {
		fmt.Println("Error printing numbers map: ", err.Error())
	}
}

func printMap(m *bpf.Map, keyStruct interface{}, valueStruct interface{}) error {
	keySize := bpf.GetStructSize(keyStruct)
	valueSize := bpf.GetStructSize(valueStruct)

	iter := m.Iterate()
	for iter.Next() {
		keyBytes, err := bpf.GetNextKey(iter.Key(), keySize)
		if err != nil {
			return err
		}

		valueBytes, err := bpf.GetNextValue(iter.Value(), valueSize)
		if err != nil {
			return err
		}

		key := (*keyStruct.(*Connection))
		value := (*valueStruct.(*Numbers))
		bpf.ConvertStructure(keyBytes, key)
		bpf.ConvertStructure(valueBytes, value)

		fmt.Println("Key:")
		fmt.Printf("  src_port: %d\n", key.SrcPort)
		fmt.Printf("  dst_port: %d\n", key.DestPort)
		fmt.Printf("  src_ip: %d\n", key.SrcIP)
		fmt.Printf("  dst_ip: %d\n", key.DestIP)

		fmt.Println("Value:")
		fmt.Printf("  seq_no: %d\n", value.Number1)
		fmt.Printf("  ack_no: %d\n", value.Number2)
		fmt.Printf("  seq_offset: %d\n", value.Number3)
		fmt.Printf("  ack_offset: %d\n", value.Number4)
		fmt.Printf("  initial_seq: %d\n", value.Number5)
		fmt.Printf("  initial_ack: %d\n", value.Number6)

		fmt.Println()
	}
	if iter.Err() != nil {
		return iter.Err()
	}
	return nil
}