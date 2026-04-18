package main

import (
	"os"

	"github.com/bikidsx/honey-badger/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
