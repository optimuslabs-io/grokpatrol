# vhs tape for the README demo GIF.  https://github.com/charmbracelet/vhs
#
#   vhs demo.tape        # -> docs/demo.gif
#
# RECORD THIS IN A THROWAWAY VM OR CONTAINER. `make demo` generates a fixture that
# contains live indicator strings, which can trip corporate EDR on a managed machine.
# The fixture is synthetic (no real Grok install) and is never committed.
#
# After recording, uncomment the image line in README.md.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 1200
Set Height 760
Set Padding 20
Set Theme "Dracula"

# Build the tool and a synthetic compromised host, then scan it. Expect COMPROMISED.
Type "make demo"
Sleep 500ms
Enter
Sleep 7s

# Hold on the verdict so the GIF ends on the answer, not a blank prompt.
Sleep 2s
