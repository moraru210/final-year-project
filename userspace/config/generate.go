//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

const (
	templateFile  = "template"
	outputFile    = "../lb/structs.go"
	maxClientsVar = "MAX_CLIENTS"
	maxServersVar = "MAX_SERVERS"
)

func main() {
	args := os.Args[1:]
	if len(args) != 2 {
		fmt.Printf("Usage: go run generate.go <MAX_CLIENTS> <MAX_SERVERS>\n")
		os.Exit(1)
	}

	maxClientsStr := args[0]
	maxClients, err := strconv.Atoi(maxClientsStr)
	if err != nil {
		fmt.Printf("Invalid value for MAX_CLIENTS: %s\n", maxClientsStr)
		os.Exit(1)
	}

	maxServersStr := args[1]
	maxServers, err := strconv.Atoi(maxServersStr)
	if err != nil {
		fmt.Printf("Invalid value for MAX_SERVERS: %s\n", maxClientsStr)
		os.Exit(1)
	}

	if maxClients <= 0 {
		fmt.Printf("Invalid value for environment variable %s: %d\n", maxClientsVar, maxClients)
		os.Exit(1)
	}

	if maxServers <= 0 {
		fmt.Printf("Invalid value for environment variable %s: %d\n", maxServersVar, maxServers)
		os.Exit(1)
	}

	templateBytes, err := ioutil.ReadFile(templateFile)
	if err != nil {
		fmt.Printf("Failed to read template file: %v\n", err)
		os.Exit(1)
	}

	templateContent := string(templateBytes)
	templateContent = strings.Replace(templateContent, "MAX_CLIENTS_VAL", strconv.Itoa(maxClients), 2)
	templateContent = strings.Replace(templateContent, "MAX_SERVERS_VAL", strconv.Itoa(maxServers), 2)

	err = ioutil.WriteFile(outputFile, []byte(templateContent), 0644)
	if err != nil {
		fmt.Printf("Failed to write output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %s with MAX_CLIENTS=%d\n", outputFile, maxClients)
}
