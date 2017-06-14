package main

import (
	"io/ioutil"
	"os"

	"github.com/staaldraad/rpchproxy/lib/utils"
)

func main() {
	utils.Init(os.Stdout, os.Stdout, ioutil.Discard, os.Stderr)
	utils.Info.Println("welcome")

}
