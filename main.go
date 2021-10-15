package main

import (
	"fmt"

	"github.com/bhoriuchi/voltron/cli"
)

func main() {
	if err := cli.NewCommand().Execute(); err != nil {
		fmt.Println(err)
	}
}
