// pclnsym resolves Go function entry addresses from .gopclntab, which survives -s -w stripping.
// Mode B uses these addresses to attach uprobes to the shipped binary without rebuilding it.
//
//	pclnsym <binary> <func-suffix>...   (an argument starting with ~ matches anywhere in the name)
package main

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
	"os"
	"strings"
)

func main() {
	f, err := elf.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	pcln := f.Section(".gopclntab")
	text := f.Section(".text")
	if pcln == nil || text == nil {
		fmt.Println("no .gopclntab or .text section")
		os.Exit(2)
	}
	data, err := pcln.Data()
	if err != nil {
		panic(err)
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil {
		panic(err)
	}
	for _, fn := range tab.Funcs {
		for _, want := range os.Args[2:] {
			if (strings.HasPrefix(want, "~") && strings.Contains(fn.Name, want[1:])) || strings.HasSuffix(fn.Name, want) {
				file, line, _ := tab.PCToLine(fn.Entry)
				fmt.Printf("%#x\t%s\t%s:%d\n", fn.Entry, fn.Name, file[strings.LastIndex(file, "/vendor/")+1:], line)
			}
		}
	}
}
