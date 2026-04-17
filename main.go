package main

import (
	"os"

	"github.com/bikidas/honey-badger/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
