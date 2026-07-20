# detkit demo — generate the GIF with:  vhs detkit-demo.tape
# Prereqs: `go install github.com/charmbracelet/vhs@latest` (or brew install vhs),
#          run from the detkit repo root, and `pip install -e .` first.
# Uses GNU sed (Linux/WSL). On macOS, change `sed -i` to `sed -i ''`.

Output detkit-demo.gif

Require detkit

Set Shell bash
Set Theme "Dracula"
Set FontSize 18
Set Width 1200
Set Height 680
Set Padding 24
Set TypingSpeed 45ms

Hide
Type "clear"
Enter
Show

Type "# A Sigma rule ships with sample events saying what it should catch:"
Enter
Sleep 1s
Type "detkit test examples/rules"
Enter
Sleep 3s

Type "# A teammate 'tidies up' the rule and quietly breaks the detection..."
Enter
Sleep 1s
Type "sed -i 's/whoami/whoamiXYZ/' examples/rules/whoami_execution.yml"
Enter
Sleep 1200ms

Type "# detkit catches it. Non-zero exit means CI blocks the pull request:"
Enter
Sleep 800ms
Type "detkit test examples/rules; echo exit=$?"
Enter
Sleep 4s

Type "# Revert -> green again."
Enter
Sleep 800ms
Type "sed -i 's/whoamiXYZ/whoami/' examples/rules/whoami_execution.yml"
Enter
Type "detkit test examples/rules; echo exit=$?"
Enter
Sleep 3500ms
