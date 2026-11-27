---
title: "The Pultec Low End Trick"
slug: "the-pultec-low-end-trick"
date: "2026-11-28"
updatedAt: "2026-11-28T05:15:00Z"
status: "published"
pinned: false
tags: ["Mixing", "Mastering", "Notes"]
summary: "Why boosting and attenuating the same frequency on a passive Pultec EQP1A adds deep sub weight while scooping out low mid mud."
coverImage: ""
---

Try boosting and cutting the same frequency on a standard digital EQ and the two moves cancel out flat. Try it on a **Pultec EQP1A** (or Logic’s built in **Vintage Tube EQ** and the **UAD Pultec Passive EQ Collection**) and you get massive sub weight alongside a cleaner midrange.

> Boost the sub fundamental. Let the attenuation scoop the mud sitting right above it.

## Why It Doesn’t Cancel Out

Unlike active digital EQs, the original Pultec EQP1A shapes tone with a passive network of inductors, capacitors, and resistors. Passive components cannot amplify anything on their own. They drop the whole signal by roughly 20 dB of insertion loss, then pass it through a vacuum tube makeup stage that brings the level back up with subtle transformer warmth.

Even though a single frequency switch (`20`, `30`, `60`, or `100 Hz`) controls the low band, **Boost** and **Attenuate** run through two separate internal filter curves:

* **Low Boost:** Acts as a very broad low shelf that lifts sub frequencies while spilling upward into the low mids (`100 to 300 Hz`).
* **Low Attenuate:** Uses a different filter slope whose turnover frequency sits roughly half an octave to a full octave higher up.

When you turn both knobs up together, the boost holds up the deep bottom end while the higher attenuation curve carves a dip right through the boxy low mids sitting above it.

![Frequency response showing the Pultec boost shelf, higher attenuation turnover, and resulting low mid mud scoop](writings/media/20261128-051500-pultec-trick-curve.png)

## Starting Settings by Instrument

Ignore the `0 to 10` scale printed around Pultec dials. Those markings are not calibrated in decibels, so trust your ears first:

1. **Vocals (`100 Hz` Band):** Start on `100 Hz` with **Boost around `4`** and **Atten around `6`** to add chest weight without clouding the mix, then open `12 kHz` high end air (**Q around `8`**, **Boost around `2`**).
2. **Bass Guitar (`100 Hz` Band):** Set `100 Hz` with **Boost around `5`** and **Atten around `6`**, tweaking until low notes stay fat without masking the kick.
3. **Kick Drum & Master Bus (`20`, `30`, or `60 Hz`):** Pick `20` or `30 Hz` for deep sub punch on kick drums (`200 to 400 Hz` dip), or `60 Hz` on a full mix (`Boost 3 to 4`, `Atten 3 to 4`) after bus compression, paired with `10`, `12`, or `16 kHz` for subtle top sheen.

*Adapted in part from Island Recording Studios’ Home Recording Bootcamp mixing guides.*
