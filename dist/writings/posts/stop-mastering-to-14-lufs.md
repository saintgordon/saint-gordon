---
title: "Stop Mastering to -14 LUFS"
slug: "stop-mastering-to-14-lufs"
date: "2026-11-27"
updatedAt: "2026-11-27T07:18:00Z"
status: "published"
pinned: false
tags: ["Mastering", "Mixing", "Notes"]
summary: "Why chasing Spotify normalization leaves masters thin, where modern commercial records actually sit between -12 and -8 LUFS, and the exact EQ and compression chain order."
coverImage: ""
---

Every independent producer hears the same advice eventually: master your song to -14 LUFS so Spotify won’t turn it down. Follow that rule blindly and your track will sound thinner, quieter, and smaller than almost every record next to it on a playlist.

> Master to make the song hit as cleanly and emotionally as possible, not to chase an algorithm target.

## The Myth Behind -14 LUFS

Streaming platforms normalize playback levels using loudness algorithms, which only adjust playback volume after upload. They do not magically add punch, density, or limiter glue to a quiet bounce.

In the real world, dense modern records usually sit between **-12 LUFS and -8 LUFS**. Pushing above -8 LUFS enters very loud territory where punchy drums easily squash flat, while sparse acoustic or vocal driven songs with minimal sub bass naturally belong closer to -14 LUFS. Let the arrangement dictate the loudness, not a single blanket number.

![Export headroom and commercial integrated loudness targets for mastering](writings/media/20261127-075002-lufs-target-window.png)

## Fresh Ears First, Chain Order Second

Never master a song on the same day you mix it if you can avoid it. Sleep on the bounce, come back with rested ears, and listen front to back once without touching a single plugin so you hear real tonal issues instead of habits.

Once you load a mastering chain, the processing order protects your mix:

1. **EQ Phase 1 (Before Compression):** Use a transparent digital EQ to clean up leftover mud (`200 to 400 Hz`) and gently tame sharp resonances. If you find yourself carving aggressively, step back into the mix and fix it there.
2. **Subtle Bus Compression:** Insert a clean VCA compressor (like a Focusrite Red 3 or SSL style bus comp) at `1.5:1 to 3:1` aiming for just `1 to 3 dB` of gain reduction. Time the release to the song’s tempo so the whole mix breathes with the groove.
3. **EQ Phase 2 (After Compression):** Shape tone and polish *after* the compressor with musical curves, such as a Pultec at `60` or `100 Hz` for tight weight, `10` to `16 kHz` for finished top sheen, or a tiny `0.5 to 2 dB` presence lift at `4 to 5 kHz`. Boosting after compression stops your EQ moves from driving harder into the compressor.
4. **Stereo Check & Limiting:** Keep sub bass frequencies centered (especially if pressing vinyl), verify mono compatibility, and push into your limiter while watching True Peak headroom.

Drop your final master alongside a commercial reference into [Master Clash](https://saintgordon.vercel.app/tools#tool-master-clash) for loudness matched blind comparison, then audit real Spotify and Apple Music turn down inside [Pre Flight](https://saintgordon.vercel.app/tools#tool-pre-flight).
