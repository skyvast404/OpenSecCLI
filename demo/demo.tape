# VHS demo script — generates demo.gif
# Install: go install github.com/charmbracelet/vhs@latest
# Run: vhs demo/demo.tape

Output demo/demo.gif

Set FontSize 14
Set Width 1200
Set Height 600
Set Theme "Dracula"
Set Padding 20

Type "# OpenSecCLI — One CLI for your entire security workflow"
Enter
Sleep 1s

Type "opensec crypto hash-id 5d41402abc4b2a76b9719d911017c592"
Enter
Sleep 3s

Type "opensec vuln header-audit --url https://httpbin.org/get"
Enter
Sleep 5s

Type "opensec pentest jwt-test --token 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'"
Enter
Sleep 4s

Type "opensec doctor"
Enter
Sleep 4s

Type "# 84 commands · 30 AI Skills · Zero config"
Enter
Sleep 2s
