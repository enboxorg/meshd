package main

import (
	"fmt"
	"os"
)

const usage = `dwn-mesh - Decentralized WireGuard mesh networking via DWN

Usage:
  dwn-mesh <command> [arguments]

Commands:
  init              Generate DID, WireGuard keys, and start local DWN
  network create    Create a new mesh network
  network join      Join an existing mesh network
  network leave     Leave the current mesh network
  peer add          Add a peer to the mesh (admin)
  peer remove       Remove a peer from the mesh (admin)
  peer list         List all peers and their status
  status            Show mesh status and active tunnels
  up                Start the mesh agent daemon
  down              Stop the mesh agent daemon

Flags:
  -h, --help        Show this help message
  -v, --version     Show version information
`

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "-h", "--help", "help":
		fmt.Print(usage)
	case "-v", "--version", "version":
		fmt.Printf("dwn-mesh %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "dwn-mesh: unknown command %q\n", os.Args[1])
		fmt.Fprintf(os.Stderr, "Run 'dwn-mesh --help' for usage.\n")
		os.Exit(1)
	}
}
