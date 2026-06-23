# Capture instructions

Two **optional** animated/still captures that upgrade the README. The README already
renders without them (it ships `public/poster.svg` as the hero and social card); drop
these into `docs/` and add them back into the Highlights section when recorded.

## docs/flip-to-patched.gif

The signature "aha" moment for the lab.

- Start: oscilloscope exhibit, both trace cards already populated (click **Run 100 measurements** before recording).
- Frame the **Flip overlay** panel (it sits below the two trace cards, labelled "Signature moment").
- 1 second: hover over **Vulnerable path** (the active chip).
- 2 seconds: click **Flip to patched**. The red line dims, the green line lights up on the same shared scale.
- 1 second: pause on the "Spread collapse" metric in the readout.
- Loop the GIF. Around 4-5s, 720p+, < 4MB.

## docs/attack-progression.png

A still that proves "the attack actually works."

- Run the live attack on the **Vulnerable path** until at least 50% recovery.
- Capture the recovery grid (the 768-cell strip), the milestone strip, and the attack log together.
- Crop so the gold "Recovered key matches secret" pill is visible if the run completed.
- 1600px wide is plenty. PNG, not JPEG (text crispness matters).
