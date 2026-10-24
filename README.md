# Wharf

Wharf is OpenPak's Xbox 360 emulator, built on [Xenia Edge](https://github.com/has207/xenia-edge),
a fork of Xenia Canary. It aims to boot the console's own dashboard and system
software and connect it to OpenPak's replacement Xbox 360 services, in the same
way Harbor does for the Switch.

Wharf is an independent project. Xenia Edge remains our upstream base; this is
not an official Xenia or Xenia Edge release. The work lives on the `wharf`
branch of this repository.

**Status:** Experimental (boots, online incomplete)

## Not affiliated

Wharf is independent and is not endorsed by the Xenia or Xenia Edge projects. It
is not affiliated with Microsoft. Xbox, Xbox 360 and related names are
trademarks of their respective owners.

## What works today

- Builds on Linux with Clang (`xb build --config=release --disable-lto`).
- Boots the 17559 Xbox 360 dashboard, with the real `xam.xex` loaded
  (`--real_xam=true`), through its own first-run setup to the HOME screen.
- A virtual network card gives the guest a DHCP address, DNS and TCP/UDP through
  user-mode NAT, with no root needed.
- The dashboard's Test Xbox Live Connection page passed against OpenPak's
  deployed Xbox 360 services on 2026-10-16, reporting Network, Internet and
  Xbox Live as connected. That test used Wharf only.
- The sign-in applet's Download Profile path reaches OpenPak's account service
  and gets through several of its steps.

Not verified: a completed Xbox Live sign-in, any game, any retail console
against the same services, and any performance or compatibility claim. At last
check, HOME content from Xbox Live showed "temporarily unavailable".

## Connecting to OpenPak

Wharf has no separate login dialog yet. The guest runs the dashboard's own sign-in
flow, and its network traffic is resolved to OpenPak's Xbox 360 services (Kerberos
authentication, gateway and information services) backed by the shared account
core. A first-run onboarding flow like Harbor's is planned, not built.

You supply the Xbox 360 system software and any games yourself, from a console
you own. OpenPak provides none and never will. Create an account at
https://openpak.org.

## Downloads

No public build yet. The tags in this repository mark upstream commits and are
not Wharf releases. Releases will appear at https://github.com/openpak/wharf/releases.

## Building from source

Follow [docs/building.md](docs/building.md), inherited from Xenia Edge:
`xb slang` to fetch the shader compiler, `xb setup`, then `xb build`. On Linux
this uses CMake and Ninja; the working configuration is Clang 22 with LTO
disabled. Wharf's networking uses libslirp (a submodule) and the system
`glib-2.0` library, on Linux only. Some of this work is still in progress and
may not be in your checkout yet.

## Known limitations

- Xbox Live client code that ships only in console flash (the Live sign-up and
  parts of the Live client) is absent from public updates, so "Join Xbox Live" and
  full account creation do not work yet.
- Sign-in has not completed. The deployed services only partly cover the sign-in
  applet's requests so far (account information steps are still being added).
- Input is incomplete: scripted D-pad navigation on HOME is unreliable.
- Wharf inherits Xenia Edge's gaps: many games do not run, and macOS is the
  least tested port. There is no Wharf Android build.
- This is research software with a lot of temporary diagnostics in the tree.

## Contributing and support

Report bugs at https://github.com/openpak/wharf/issues, not with Xenia. To
report a security problem, contact the OpenPak maintainers privately through
the contact on https://openpak.org and do not open a public issue. See
[.github/CONTRIBUTING.md](.github/CONTRIBUTING.md), inherited from Xenia. It
requires that information comes from legally owned software and public sources,
not from Microsoft development kits. Most useful: testing the dashboard flow,
Xbox Live protocol notes derived from the dashboard's own behavior, and
help with the guest kernel gaps.

## License and acknowledgements

BSD 3-Clause, from Xenia (Copyright 2015 Ben Vanik); see [LICENSE](LICENSE).
Thanks to the Xenia, Xenia Canary and Xenia Edge developers, whose work Wharf
builds on.

The original Xenia Edge README is kept in [README.upstream.md](README.upstream.md).
