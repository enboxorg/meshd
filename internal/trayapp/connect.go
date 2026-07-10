package trayapp

import "strings"

const macOSTerminalScript = `on run argv
  tell application "Terminal"
    activate
    do script (item 1 of argv)
  end tell
end run`

func connectShellCommand(executable string, args []string) string {
	command := make([]string, 0, len(args)+1)
	command = append(command, shellQuote(executable))
	for _, arg := range args {
		command = append(command, shellQuote(arg))
	}
	return strings.Join(command, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
