TrustVision - offline Windows app
=================================

WHAT THIS IS
  A self-contained, air-gapped copy of TrustVision. It carries its own Python + PyTorch
  engine and its own Node runtime, so it runs on any 64-bit Windows 10/11 machine with
  NOTHING to install. Nothing here talks to the internet.

HOW TO RUN
  1. Extract this whole folder anywhere (Desktop, USB stick, wherever).
  2. Double-click  TrustVision.vbs
  3. The first time, Windows may show "Windows protected your PC" (because the app is not
     code-signed). Click  More info  ->  Run anyway.  This is expected for an unsigned app.
  4. The app window opens after a few seconds. On the FIRST launch, the analysis engine
     keeps loading in the background for up to a minute or two (PyTorch is large and your
     antivirus scans it once). You can sign in and look around straight away; the top bar
     shows "engine online" the moment analysis is ready. Later launches are much faster.

  To shut it down: double-click  Stop TrustVision.vbs

SIGN IN
  - "Read-only evaluation session" needs no password - good for looking around.
  - To run analyses, sign in as:
        username:  admin
        password:  TrustVision#2026
    Change this in Settings after the first login.

WHERE YOUR DATA LIVES
  Everything you produce (the evidence database, the signing key, issued passports) stays in
  the  data\  folder next to this file. Delete it to start clean. Back it up to keep your work.

NOTES
  - Requires 64-bit Windows and roughly 2 GB of free RAM for model analysis.
  - It listens only on 127.0.0.1 (this machine); no one else on the network can reach it.
  - If it does not open, run  bin\run.ps1  directly to see any error.
