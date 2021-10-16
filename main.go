package main

import (
	"github.com/bhoriuchi/voltron/pkg/cli"
	"github.com/fatih/color"
)

func main() {
	if err := cli.NewCommand().Execute(); err != nil {
		color.Red("\n%s\n", err)
	}
}
