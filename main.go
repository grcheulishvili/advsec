// advsec is a context-aware UNIX pipeline recommendation engine. Piped the
// output of tools like nmap, file, curl, gdb, or journalctl, it identifies the
// operational context, checks local host capability, and prints prioritized,
// executable next-step commands.
package main

import "github.com/grcheulishvili/advsec/cmd"

func main() {
	cmd.Execute()
}
