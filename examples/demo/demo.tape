# Records docs/assets/demo.gif and demo.mp4. Run from the repo root:
#   vhs examples/demo/demo.tape
# Needs VHS (brew install vhs). BOUNCER_DEMO_PACE=1 slows the demo so it can be read.

Output docs/assets/demo.gif
Output docs/assets/demo.mp4

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 700
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set Framerate 24

Env BOUNCER_DEMO_PACE "1"
Env PS1 "$ "

Hide
Type "uv sync --all-packages -q && rm -rf examples/demo/out && clear"
Enter
Sleep 3s
Show

Sleep 500ms
Type "uv run python examples/demo/run_demo.py"
Sleep 600ms
Enter
# The paced run takes ~26s, then the last line holds for ~2.5s. A fixed sleep,
# because Wait+Screen cannot see past the first screenful.
Sleep 28.5s
