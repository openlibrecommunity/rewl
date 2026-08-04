//go:build mage

package main

import (
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

func Build() error {
	return sh.Run("go", "build", "-o", "build/rewl", ".")
}

func Run() error {
	mg.Deps(Build)
	return sh.RunV("./build/rewl")
}

func Clean() error {
	return os.RemoveAll("build")
}
