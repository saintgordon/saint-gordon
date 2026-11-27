---
title: "Pre Mix & Pre Master Bounce Hygiene"
slug: "pre-mix-and-pre-master-bounce-hygiene"
date: "2026-11-27"
updatedAt: "2026-11-27T07:16:00Z"
status: "published"
pinned: false
tags: ["Studio", "Mixing", "Mastering"]
summary: "The tracking gain, headroom, sample rate, and export checks that prevent ruined vocal stems and clipped bounces before mixing or mastering begins."
coverImage: ""
---

Most mix headaches aren’t solved with fancy plugins. They happen before the mix session even opens, or right at the moment someone hits export without checking their meters.

> Great masters start with clean stems and unclipped headroom.

## Before Mixing: Tracking & Stem Hygiene

Whether you are tracking vocals in a bedroom or exporting multitracks for a collaborator, lock down the basics early:

* **Set Metering to Pre Fader:** Keep your DAW meters set to Pre Fader while recording so pulling a channel fader down doesn’t hide a preamp clipping on the way in.
* **Gain Stage for the Loudest Chorus:** Record a 10 to 20 second test clip of the loudest vocal belt or heaviest guitar strum, and dial preamp gain so peaks land around -10 dBFS. Plenty of headroom means zero digital clipping when the take gets emotional.
* **Lock Your Sample Rate:** Stick to one consistent rate (`44.1 kHz` or `48 kHz`) across your interface, DAW session, and exports.
* **Print Clean, Aligned Stems:** Every stem should start cleanly at `0:00` with matching tail lengths and zero accidental stereo reverb baked onto dry mono vocals. Run them through [Stem Check](https://saintgordon.vercel.app/tools#tool-stem-check) before sending stems to anyone else.

## Before Mastering: Pre Master Export Rules

If something still feels harsh, muddy, or buried in the mix, fix it in the mix. Don’t leave broken balances hoping mastering will rescue them later.

1. **Strip Temporary Master Limiters:** Remove any auto mastering plugins or quick loudness limiters from your master bus before bouncing, while keeping your intentional mix bus EQ or glue compression intact.
2. **Leave 2 to 6 dB of Headroom:** Confirm there is zero red clipping on the stereo out and aim for mix peaks between -6 dBFS and -2 dBFS so your mastering chain has room to breathe.
3. **Export at Native Resolution:** Bounce a lossless WAV matching the exact resolution you tracked and mixed in (for example, `48 kHz, 24 bit`) instead of upsampling or crushing down to MP3.
4. **Protect Your Starts & Fade Tails:** Leave half a second of clean space before the first transient and let every reverb tail decay completely to silence. Mastering handles final top and tail trims, while broken fade outs need fixing inside the mix.

Drop your pre master or finished master into [Pre Flight](https://saintgordon.vercel.app/tools#tool-pre-flight) to catch clipping bursts, intersample peaks, or low end phase issues before release.
