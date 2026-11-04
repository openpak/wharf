# Changelog

## v0.1.1 (2026-11-04)

- `WHARF_NIC_HTTPLOG=1` logs the first bytes of port-80 TCP payloads in both directions (dev aid, off by default).
- Writable host directory for `\Device\Harddisk0\Cache` (XAM stages TK_* temp files there).
- Verified end to end after a Live sign-in: `sap/online/system.online.manifest.<SOMRevision>` is downloaded from x360-som, passes XAM verification (container and body magic, SHA1, revision) and is stored; the refresh thread then exits 0. The `.lex` module fetch is lazy and not yet exercised. The scripted `pad` file input is not available in this build.

## v0.1.0 (2026-11-04)

First tagged Wharf release (Xbox 360 emulator fork of Xenia Edge, real 17559 dash).

- Mount a writable host directory (storage root `sap`) at `\Device\Harddisk0\SystemAuxPartition`, the target of XAM's `\sap` link, so the online module manifest can be stored at `\sap\online`.
- real_xam: a helper thread calls XAM export 0x65A (`XampDemandUpdateRefreshManifestDuringLogon`, 0x8168BD30) every 15 s once app 0xFE exists, until `sap/online` exists. Needs the Live config (SOMRevision, UpdateUriRoot1), so it only succeeds after a sign-in. Disable with `WHARF_NOSOMREFRESH=1`.
- Log the exit code of real_xam helper threads (`XThread '...' exit code`), which showed the refresh failing with 8007065B before sign-in and D000003A (path not found) without the SystemAuxPartition mount.
