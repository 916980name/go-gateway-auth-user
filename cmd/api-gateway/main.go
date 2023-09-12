package main

import (
	"os"

	gateway "api-gateway/internal/api-gateway"
)

func main() {
	command := gateway.NewCommand()
	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}
