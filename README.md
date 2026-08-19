# IP Guardian

**Stops your apps the moment your connection stops being the one you trusted.**

A small macOS app that watches the connection your chosen applications are
using. If the VPN drops, the proxy changes, or your traffic starts leaving from
somewhere else, the protected apps are frozen within milliseconds and closed if
the change is confirmed — before they can say anything over the new connection.

macOS 13 or newer · Apple Silicon and Intel · 3.3 MB · no dependencies

---

## Who it is for

Anyone whose work depends on traffic leaving through a particular connection: a
VPN, a proxy, or a specific network. IP Guardian does not create that connection
— it makes sure your apps stop using the internet the instant that connection is
no longer the one you approved.

## Install

1. Download `IP Guardian.zip` from the [latest release](../../releases/latest).
2. Unzip it and drag **IP Guardian** into your Applications folder.
3. Open it. macOS refuses the first launch because the app has no paid Apple
   Developer signature: go to **System Settings › Privacy & Security**, press
   **Open Anyway**, and open it again. macOS asks only once.

To remove it, quit the app and drag it to the Trash.

## Using it

1. **Add the applications you want protected** — a browser, a chat client,
   anything that must not talk over the wrong connection.
2. **Choose a rule** and, for Same Country, the countries you allow.
3. **Close those applications**, then press **Start Protection**. The trusted
   connection is established while nothing is sending traffic.

From then on your apps run normally until something changes. Turning Protection
off on a verified connection simply leaves them running — ending a session never
costs unsaved work.

## The two rules

**Exact IP** — the strictest. The public address has to stay exactly what it was
when Protection started. Best when your VPN or proxy gives you one stable exit.

**Same Country** — the address may change as often as it likes, as long as the
connection stays in one of up to three countries you choose. Best when your VPN
or proxy moves between exits: a VPN left on automatic, or a proxy that answers
from several exits at once.

Whichever rule you pick, the route itself is always watched. If the VPN or proxy
drops, your apps are closed regardless.

## Why you can leave your apps with it

**Freezes first, asks questions second.** The moment the network changes, your
protected apps are frozen — before anything is known about the new connection.
Checking happens while they are already stopped, not before.

**Never closes an app on a guess.** A timeout, an unreachable service or a brief
outage never closes anything. Apps wait, frozen, until the connection is verified
again.

**Agreement, then confirmation.** Independent services have to agree on what they
see, and a change has to be confirmed repeatedly before a single application is
closed.

**Survives its own failure.** If IP Guardian is force quit or crashes while your
apps are frozen, they are released automatically. Nothing stays stuck.

## Privacy

Country flags ship inside the app, so nothing outside your Mac learns where you
are connected. The activity list stays in memory and disappears when you quit,
and the trusted connection is never written to disk — every launch starts with
Protection off.

## What it will not do

**It is not a firewall.** IP Guardian reacts quickly, but it cannot guarantee
that zero packets leave between a network change and the apps being stopped. A
true zero-packet kill switch needs a system firewall or a Network Extension.

**A restricted network can stop verification.** Confirming the connection means
reaching independent services on the internet. Behind a network or proxy that
carries only part of it, some cannot be reached and verification fails even
while ordinary browsing works. Nothing is closed when that happens: the apps stay
frozen and verification keeps retrying.

**Closing apps is a force close.** When a connection is confirmed unsafe, the
protected apps are closed without being allowed to run again first — that is the
point, but unsaved work in them is lost.

## Build from source

Requires Apple's Command Line Tools. Full Xcode is not needed.

```bash
xcode-select --install
bash ./build_app.sh
```

This writes `dist/IP Guardian.app` and a shareable `dist/IP Guardian.zip`, built
for both Apple Silicon and Intel. `install.sh` builds and installs straight into
`~/Applications`; `uninstall.sh` removes it.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

Developed by Amir Mokhtari · dev.mokhtari@gmail.com
