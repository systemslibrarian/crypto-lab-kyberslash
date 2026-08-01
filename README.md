# crypto-lab-kyberslash

## What It Is

Browser-based educational simulation of the KyberSlash timing attacks on ML-KEM (Kyber), based on the 2025 TCHES CHES Best Paper by Daniel J. Bernstein, Karthikeyan Bhargavan, Shivam Bhasin, Anupam Chattopadhyay, Tee Kiah Chia, Matthias J. Kannwischer, Franziskus Kiefer, Thales B. Paiva, Prasanna Ravi, and Goutam Tamvada. The demo shows how integer division by the Kyber modulus q = 3329 in the reference `poly_tomsg` and `poly_compress` functions leaks secret information through variable division timing on ARM Cortex-A7 and Cortex-M4 targets. Because JavaScript cannot measure real CPU division latency reliably, the browser uses a deterministic timing model built from the paper's own measurements instead of real clock measurements. The lab shows the vulnerable code, the upstream multiply-and-shift replacement verbatim from the pq-crystals fix commit, a live attack simulation that recovers the vulnerable secret key, and the failed attack against the patched implementation.

The one thing the lab refuses to hand-wave is *what actually performs the division*, because that is target-specific and it is the whole point of the paper. On the paper's headline target — a Raspberry Pi 2 (BCM2836, Cortex-A7) with gcc 8.3.0 `-Os` — **no `udiv` instruction executes at all**: gcc compiles for an ABI that does not guarantee a divide instruction, so the division becomes a call to the `__divsi3` software routine, whose cost jumps by **20 cycles at numerator 3,329**, a further **2 at 4,096** and a further **1 at 8,192** (§5.1.1). Since the numerator is `2t + 1664`, those land at coefficients **t = 833, 1216 and 3264** (§5.1.2). The Cortex-M4 (STM32F407VG) target is the one with a hardware `udiv`, whose latency is a step function of the numerator — 2 to 12 cycles, crossing over at 1, 2¹¹, 2¹⁵, 2¹⁹, 2²³, 2²⁷, 2³¹ for d = 3329 (Table 4) — and only the 2¹¹ = 2,048 crossover falls inside the 1,664–8,320 numerators this line can produce.

So the lab draws that causal chain on screen for whichever target is selected: a **division-cost band number line** where the target's real cost steps are colored bands, the unreachable ends of the number line are shaded out, and the current numerator lands in one band, so a learner sees the numerator's magnitude *pick* the cost; a **single-coefficient two-probe walkthrough** that hand-cranks the attack for one secret using the two probes straddling that target's biggest in-range step (`t=832`/`t=833` on Cortex-A7, `t=191`/`t=192` on Cortex-M4), the device adding the hidden `s ∈ {−1,0,+1}`, each numerator landing below or above the step, and the fast/slow truth table filling in to reveal the coefficient before the full 768-cell grid runs the same trick 768 times; and a **Barrett-reduction intuition panel** that puts the vulnerable `/ q` beside the patched `(x × 1,290,168) >> 32` and shows the same band graphic collapsing to one fixed cost, making "constant-time" mechanical rather than a slogan. Every band figure carries its own source line and states which of its numbers are illustrative. First-mention jargon (`__divsi3`, `udiv`, `poly_tomsg`, Barrett reduction) is glossed inline, and the raw `n/k/q/η/du/dv` parameters sit behind a disclosure so newcomers meet the story before the parameter dump.

## When to Use It

- Understanding why “NIST standardized” does not mean “every implementation is safe”
- Teaching timing side channels in the context of post-quantum cryptography
- Explaining constant-time programming discipline to developers deploying ML-KEM
- Comparing KyberSlash1 and KyberSlash2 as concrete examples of secret-dependent division leakage
- Understanding why verified and side-channel-audited implementations such as Cryspen and HACL* matter
- Evaluating what questions to ask about a real PQ deployment on its actual target hardware
- Do NOT use it for attacking real systems; the affected libraries were patched between December 2023 and 2024 (a couple later, and two not at all) and this repository is an educational simulation only

## Live Demo

**[systemslibrarian.github.io/crypto-lab-kyberslash](https://systemslibrarian.github.io/crypto-lab-kyberslash/)**

Step through a side-by-side oscilloscope where the vulnerable trace swings with secret-dependent division timing while the patched Barrett-reduction trace stays flat, then run a live attack that reconstructs all 768 ML-KEM-768 secret coefficients one by one and verifies them against the real key. Toggle between a simulated Cortex-A7 (Raspberry Pi 2, `__divsi3` software division, a 20-cycle step) and a Cortex-M4 (STM32F407VG, hardware `udiv`, a 2-cycle step) and watch the whole causal chain — thresholds, probes, bands, truth table — move to that target's real numbers.

## What Can Go Wrong

- **This is a simulation.** Browsers do not expose stable instruction-level timing for CPU division, so the demo uses a deterministic step model rather than real cycle counts from your machine. The *steps* are the paper's: the Cortex-M4 numbers are Table 4's absolute measured `udiv` cycle counts, and the Cortex-A7 numbers are §5.1.1's measured +20/+2/+1 jumps sitting on an invented base cost — the paper never reports `__divsi3`'s absolute cost, so that base, the measurement jitter, and the patched path's fixed cost are illustrative and are labelled as such on screen.
- **The lab resolves three secret values, not five.** ML-KEM-768 samples its secret from CBD with η1 = 2, so real coefficients lie in −2…+2. This lab collapses them to {−1, 0, +1} because two adjacent probes distinguish exactly three values; the paper's real attack instead scales the secret by attacker-chosen multipliers `û` and separates the full range. The key here is a reduced teaching toy, not a standards-conformant ML-KEM-768 secret.
- **The vulnerabilities shown here are patched upstream.** The pq-crystals reference code, PQClean, liboqs, pqm4, botan, aws-lc, circl and the rest of the affected set were all fixed by 2024 (PQClean's aarch64 backend in September 2024). Some implementations — BoringSSL's Kyber, `filippo.io/mlkem768`, libjade, and the AVX2 paths of pq-crystals and PQClean — reportedly never had the division at all. Two libraries in the project's survey were still unpatched as of August 2025, so "current" is not the same as "all".
- **Other side channels still exist.** Timing leakage is only one class of implementation failure; cache effects, EM leakage, power analysis, speculative execution, and fault injection are separate attack surfaces.
- **Compiler behavior matters.** Modern x86_64 often rewrites division by a constant into multiplication automatically, but some build configurations such as `-Os` can reintroduce actual division on certain targets.
- **Formal verification and constant-time guarantees are different properties.** A program can be functionally correct and still leak through timing if the implementation path is not side-channel-audited.

## Real-World Usage

- The KyberSlash attacks were published as **“KyberSlash: Exploiting secret-dependent division timings in Kyber implementations”** in IACR Transactions on Cryptographic Hardware and Embedded Systems 2025, issue 2, pages 209–234 (ePrint 2024/1049), and won the CHES 2025 Best Paper Award.
- The work showed two distinct vulnerabilities: **KyberSlash1** in the underlying PKE's *decryption* via `poly_tomsg`, and **KyberSlash2** in the underlying PKE's *encryption* via `poly_compress` and `polyvec_compress`. KyberSlash2 is harmless inside encapsulation, where the ciphertext is public; it becomes a key-recovery oracle because the Fujisaki-Okamoto transform re-runs encryption inside *decapsulation* on secret-derived input.
- On Raspberry Pi 2 hardware with ARM Cortex-A7, the paper's KyberSlash1 demo recovered a Kyber512 secret key in 10 out of 10 experiments in 2 to 4 hours, budgeted to give up after 7·2¹⁸ = 1,835,008 decapsulations (Table 1, §5.2). For KyberSlash2 on Cortex-M4 (Kyber768), the local attacker reading the target's own cycle counter needed **6,144** decapsulations and about four minutes end to end, 10 of 10 (§6.2.1); the more realistic remote attacker, timing from a second board, needed **24,576** decapsulations and about twenty minutes, also 10 of 10 (§6.2.2) — 24,576 is the figure Table 1 reports.
- Patching was not a single tidy pre-disclosure event. The pq-crystals reference code was fixed for KyberSlash1 on 1 December 2023, two weeks before Bernstein announced the issue publicly on 15 December; KyberSlash2 was reported and patched on 30 December, the day it became public. Everything downstream landed afterwards, in the open: cloudflare/circl 1 January 2024, liboqs 8 January, PQClean 25 January, pqm4 23 February, kyberlib 12 May, PQClean's aarch64 backend 19 September. Two libraries still carried a secret-dependent division as of the project's August 2025 survey.
- The broader lesson is the one this lab emphasizes: standardization does not remove the need for independent side-channel review on each deployment target.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-kyberslash
cd crypto-lab-kyberslash
npm install
npm run dev
```

## Related Demos

- [crypto-lab-lattice-fault](https://systemslibrarian.github.io/crypto-lab-lattice-fault/) — broader side-channel and fault surface across ML-KEM and ML-DSA.
- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — the ML-KEM scheme itself: KeyGen, Encaps, Decaps.
- [crypto-lab-hqc-timing](https://systemslibrarian.github.io/crypto-lab-hqc-timing/) — a timing oracle in another post-quantum KEM (HQC).
- [crypto-lab-ciphertext-mirror](https://systemslibrarian.github.io/crypto-lab-ciphertext-mirror/) — ML-KEM decoder and FO-transform attack surface.

## What You Learn In 3 Minutes

- **The bug**: a single `/ KYBER_Q` on a secret-dependent numerator inside `poly_tomsg` and `poly_compress` leaks key bits through variable division cost — a `__divsi3` software routine on the paper's Cortex-A7 build, a hardware `udiv` on Cortex-M4.
- **The fix**: replace the divide with a multiply and a shift, so the secret path becomes constant-time. What pq-crystals actually shipped (commit `dda29cc`, 1 December 2023) is `t <<= 1; t += 1665; t *= 80635; t >>= 28;` where `80635 = floor(2^28/3329)`; the lab's own model computes the equivalent 32-bit form `(x * (floor(2^32/q) + 1)) >> 32`, i.e. `× 1,290,168`. Both were checked to equal `floor(x / 3329)` on every numerator this line can produce.
- **The proof**: an in-browser oscilloscope shows the vulnerable mean swinging while the patched mean is flat, and a live attack reconstructs all 768 ML-KEM-768 secret coefficients purely from the modelled `poly_tomsg` division cost — each coefficient is inferred from which side of the target's cost step the timing lands on, never read directly — then verified against the real key. On the patched (constant-time) path the identical attack recovers nothing.
- **The point**: NIST standardisation is a mathematical contract; side-channel safety is a separate property and has to be audited per target. The two targets here do not even use the same *mechanism*: the Cortex-A7 build calls a software divider, the Cortex-M4 executes a hardware one, their cost steps land at completely different numerators, and `-Os` can reintroduce division on platforms x86_64 normally avoids.

## Highlights

![KyberSlash — a vulnerable timing trace swings while the patched trace stays flat, and the 768-coefficient ML-KEM-768 secret key is recovered](public/poster.svg)

- **Why division leaks** — a division-cost band number line makes the invisible visible: the numerator's magnitude picks a cost band, so the clock moves with the secret. The bands are the selected target's measured steps, the unreachable numerators are shaded out, and the figure states its own source.
- **Two-probe walkthrough** — one coefficient recovered in slow motion (probes `t=832`/`t=833` on Cortex-A7, `t=191`/`t=192` on Cortex-M4, the step crossing, the fast/slow truth table) so the mass recovery reads as "the same trick 768 times."
- **Barrett in 30 seconds** — the vulnerable divide sits beside the patched multiply-and-shift, and the band graphic goes flat, so "constant-time" is shown, not asserted.
- **Flip to patched** — the same dataset on the same axes; the vulnerable signal swings and the patched signal goes flat. The signature "aha" moment.
- **Live recovery** — 768 coefficients reconstructed one by one, with a gold pill that confirms a verified match against the real key.
- **Two platforms** — toggle a simulated Cortex-A7 (Raspberry Pi 2) or Cortex-M4 and the mechanism itself changes: software `__divsi3` with a 20-cycle step at coefficient 833, versus hardware `udiv` with a 2-cycle step at coefficient 192. Same bug, different physics, much narrower signal.

> Want animated captures? `docs/CAPTURES.md` has exact framing instructions for an optional `flip-to-patched.gif` and `attack-progression.png`. Drop them into `docs/` to embed them here; until then the poster above and the [live demo](https://systemslibrarian.github.io/crypto-lab-kyberslash/) carry the visuals.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
