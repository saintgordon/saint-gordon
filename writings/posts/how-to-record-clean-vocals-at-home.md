---
title: "How to Record Clean Vocals at Home"
slug: "how-to-record-clean-vocals-at-home"
date: "2026-11-28"
updatedAt: "2026-11-28T05:16:00Z"
status: "published"
pinned: false
tags: ["Studio", "Notes", "Mixing"]
summary: "How to stop bedroom comb filtering, when recording under a blanket works versus when it turns boxy, and why keeping chorus peaks around -10 dBFS saves every take."
coverImage: ""
---

Most messy bedroom vocals fail before a single plugin ever loads. Sing near a bare bedroom wall and your voice hits the plaster, bounces back milliseconds late into the mic, and collides with the direct sound. That overlap creates **comb filtering**: a hollow, boxy tunnel tone that no EQ can truly rescue later.

> Treat the first reflection behind you, reject room noise at the mic’s rear null, and keep peaks around -10 dBFS.

## Room Treatment & The Blanket Trick

Cheap thin pyramid foam (`under 1 inch`) only absorbs top end sizzle while low mid waves bounce straight through it, leaving vocals dull and boomy. For real absorption on a budget:

* **Blankets & Recording Under a Duvet:** Throwing a heavy duvet over your head kills bright wall slap immediately in an emergency, **but** pulling thin fabric tightly around a tiny space traps boxy `200 to 500 Hz` low mids because cloth cannot stop longer bass waves. Give yourself air inside instead of suffocating right on the capsule, or better yet, hang the **thickest duvet or quilt you own** behind you with a `2 to 3 inch` gap off the wall so low mids dissipate.
* **Use Your Cardioid Null:** A cardioid mic rejects sound most strongly at `180 degrees` behind the capsule. Aim the back of the mic at your computer fan or bare wall, put your heavy blanket or open coat wardrobe behind *you*, and sing straight toward the dead room behind the mic.
* **Long Term Fix:** Timber framed DIY **Rockwool panels** cost a fraction of studio brand foam and genuinely absorb down into the low mids.

![Floorplan showing thick duvet absorption behind the vocalist, 15 to 30 cm mic placement, cardioid null rejection, and -10 dBFS Pre Fader target](writings/media/20261128-051501-home-recording-acoustics.png)

## Mic, Pop Filter & Headphones

* **Pick the Mic for the Room:** In an untreated bedroom, a **dynamic mic** (`Shure SM57`, `SM58`, or `SM7B`) rejects distant room bounce far better than a sensitive condenser (`Audio Technica AT2020`, `Rode NT1`). Only switch to a `+48V` condenser when your space is controlled.
* **Distance & Plosives:** Stay **`15 to 30 cm`** off the capsule behind a **pop filter**. Getting closer adds low end proximity warmth, so keep your head steady during loud lines.
* **Closed Back Cans Only:** Track in closed back headphones (`Sony MDR7506`, `Sennheiser HD280`, `Beyerdynamic DT770 Pro`). Open back mixing headphones like `HD600s` leak metronome clicks straight onto vocal stems.

## Pre Fader Gain Staging (-10 dBFS Rule)

1. **Set Metering to Pre Fader:** Keep DAW meters on Pre Fader while tracking so pulling a playback fader down never hides a hot preamp clipping.
2. **Kill Vocal Delay:** Drop your DAW buffer around `128 samples` or switch on direct interface monitoring so you hear yourself cleanly in real time.
3. **Test the Loudest Chorus:** Record `10 to 20 seconds` of the loudest vocal part in the song and turn preamp gain until peaks hover around **`-10 dBFS`**. Leaving generous headroom ensures an emotional belt never hits red at `0 dBFS`.

Before sending dry vocal takes for mixing, drop them into [Stem Check](https://saintgordon.vercel.app/tools#tool-stem-check) to verify alignment and zero baked in effects.

*Tracking workflow adapted in part from Island Recording Studios’ Home Recording Bootcamp checklist.*
