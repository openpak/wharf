# Wharf

OpenPak's Xbox 360 emulator, built on [Xenia Edge](https://github.com/has207/xenia-edge),
a fork of Xenia Canary. It boots the console's own dashboard and system
software and connects it to OpenPak's replacement Xbox 360 services, in the same
way Harbor does for the Switch.

| | |
| --- | --- |
| Console | Xbox 360 |
| Kind | Emulator |
| Based on | [Xenia Edge](https://github.com/has207/xenia-edge) (BSD 3-Clause, as upstream) |
| Licence | BSD 3-Clause, see [LICENSE](LICENSE) |

**Status:** Experimental (boots, online verification in progress)

Wharf is an independent project. Xenia Edge remains our upstream base; this is
not an official Xenia or Xenia Edge release.

## What it does

- Builds on Linux with Clang (`xb build --config=release --disable-lto`).
- Boots the 17559 Xbox 360 dashboard, with the real `xam.xex` loaded
  (`--real_xam=true`), through its own first-run setup to the HOME screen.
- A virtual network card gives the guest a DHCP address, DNS and TCP/UDP through
  user-mode NAT, with no root needed.
- XAM's system UI (HUD, Guide, sign-in) runs on the GPU and composites over
  the title frame.

Not affiliated with Microsoft. Xbox, Xbox 360 and related names are
trademarks of their respective owners. You supply the Xbox 360 system software
and any games yourself, from a console you own. OpenPak provides none and
never will.

## Connecting to OpenPak

Wharf has no separate login dialog yet. The guest runs the dashboard's own sign-in
flow, and its network traffic is resolved to OpenPak's Xbox 360 services (Kerberos
authentication, gateway and information services) backed by the shared account
core. A first-run onboarding flow like Harbor's is planned, not built.

Create an account at https://openpak.org.

## Building from source

Follow [docs/building.md](docs/building.md), inherited from Xenia Edge:
`xb slang` to fetch the shader compiler, `xb setup`, then `xb build`. On Linux
this uses CMake and Ninja; the working configuration is Clang 22 with LTO
disabled. Wharf's networking uses libslirp (a submodule) and the system
`glib-2.0` library, on Linux only.

## Known limitations

- Xbox Live client code that ships only in console flash (the Live sign-up and
  parts of the Live client) is absent from public updates, so "Join Xbox Live" and
  full account creation do not work yet.
- Input is incomplete: scripted D-pad navigation on HOME is unreliable.
- Wharf inherits Xenia Edge's gaps: many games do not run, and macOS is the
  least tested port. There is no Wharf Android build.

## Docs

- [Protocol](docs/protocol.md)
- [Evidence](docs/evidence.md)
- [Deploy](docs/deploy.md)
- [Notes](docs/notes.md)
- [Upstream README](docs/upstream.md)
- [Building](docs/building.md)
- [CPU](docs/cpu.md)
- [CPU TODO](docs/cpu_todo.md)
- [GPU](docs/gpu.md)
- [Instruction tracing](docs/instruction_tracing.md)
- [Kernel](docs/kernel.md)
- [Style guide](docs/style_guide.md)
- [PowerPC reference](docs/ppc/)
- [Images](docs/images/)

## Contributing and support

Report bugs at https://github.com/openpak/wharf/issues, not with Xenia. To
report a security problem, contact the OpenPak maintainers privately through
the contact on https://openpak.org and do not open a public issue. See
[.github/CONTRIBUTING.md](.github/CONTRIBUTING.md), inherited from Xenia. It
requires that information comes from legally owned software and public sources,
not from Microsoft development kits.

## Licence

BSD 3-Clause, from Xenia (Copyright 2015 Ben Vanik); see [LICENSE](LICENSE).
Thanks to the Xenia, Xenia Canary and Xenia Edge developers, whose work Wharf
builds on.
