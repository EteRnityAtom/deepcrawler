package main

import "golang.org/x/term"

func termIsTerminal(fd int) bool {
	return term.IsTerminal(fd)
}
