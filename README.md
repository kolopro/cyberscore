# The Ledger — Desktop App

This is the source code for your finance tracker, wrapped as a desktop app with
Electron. You build it into a Windows installer (`.exe`) yourself, on your own
machine. That's what makes it safe: there's no third-party binary to trust —
you can read every file in this folder, and the only thing that gets installed
is what you compiled from this source.

## What's inside

- `src/App.jsx` — the finance tracker itself (unchanged from the web version)
- `electron/main.js` — the desktop shell; stores your data in a local JSON
  file, never sends it anywhere
- `electron/preload.js` — safely connects the app to that local storage
- Everything else (`vite.config.js`, `package.json`, etc.) is standard tooling
  to build and package the app

Your data is saved to `%APPDATA%\the-ledger\ledger-data.json` on your PC.
Nothing in this app phones home — the only network calls it makes are the ones
you already knew about: CoinGecko (crypto prices), Yahoo Finance (share
prices), and Frankfurter (daily exchange rates).

## Before you start

Install **Node.js LTS** (v18 or newer) if you don't already have it:
https://nodejs.org — download the "LTS" installer and run it. This gives you
`npm`, which is all you need.

## Build steps (Windows)

1. Unzip this project anywhere, e.g. `C:\Users\you\the-ledger`.
2. Open PowerShell (or Command Prompt) and go to that folder:
   ```
   cd C:\Users\you\the-ledger
   ```
3. Install dependencies:
   ```
   npm install
   ```
   This downloads Electron, React, and the other packages listed in
   `package.json` — all well-known public packages you can inspect on
   npmjs.com. Feel free to run `npm audit` afterward if you want a dependency
   security check.
4. Build the installer:
   ```
   npm run dist
   ```
   This bundles the app and packages it into a Windows installer using
   `electron-builder`. It'll take a minute or two the first time.
5. Find your installer in the `release` folder:
   ```
   release\The Ledger Setup 1.0.0.exe
   ```
6. Double-click it to install.

## About the Windows security warning

Because this `.exe` isn't signed with a paid code-signing certificate (those
cost money and require business verification), Windows SmartScreen will very
likely show **"Windows protected your PC"** the first time you run the
installer. This is standard for any self-built or indie app — it's not a sign
of a problem with this app specifically.

To proceed:
1. Click **"More info"**
2. Click **"Run anyway"**

If you want extra peace of mind before doing that:
- Right-click the `.exe` → scan it with Windows Defender, or upload it to
  virustotal.com — since you built it yourself from this source, this will
  simply confirm there's nothing unexpected inside.
- You built it, so you can also just re-read `electron/main.js` and
  `electron/preload.js` (both short) to see exactly what the app is capable
  of before installing.

If you ever want to remove the SmartScreen warning entirely, the only real
way is to buy a code-signing certificate (roughly $100–400/year from a
certificate authority) and sign the build — not necessary for personal use,
but an option if you plan to share the installer with other people.

## Useful commands

| Command | What it does |
|---|---|
| `npm run dev` | Runs the app in a browser tab for quick UI testing |
| `npm run electron:dev` | Runs the app in an actual Electron window without building an installer |
| `npm run dist` | Builds the full Windows installer in `release/` |

## Updating the app later

If you ask me for more features later, I'll give you an updated `src/App.jsx`
(or other files) — drop the new file(s) into this same project folder and run
`npm run dist` again to rebuild the installer. Your data stays put; it's
stored outside the app folder in `%APPDATA%`.
