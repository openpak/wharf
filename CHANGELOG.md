# Changelog

## v0.1.2 (2026-11-05)

- Slot-0 RSA verify is strict for XAM's manifest check (FUN_816EBE40, detected by the caller LR) when `--xsigner_public_key` is set: PKCS#1 v1.5 SHA-1 against the OpenPak content key, like the console patch that replaces slot 0. The firmware's Microsoft-signed `system.manifest` is accepted only by pinned digest (`--xsigner_firmware_digests`, comma-separated SHA-1 hex); other slot-0 callers (firmware content packages, retail key not in this tree) stay permissive. Verified: the online manifest passes (`key 0 verified true`, stored, refresh exit 0); one flipped signature byte is rejected (`key 0 verified false`, XAM exit code 8B050012, nothing stored).
- Scripted pad input restored: `WHARF_PAD_FILE=<path>` is read for comma-separated button names (`A,RIGHT,LB`, optional `NAME:polls`), each press held for `WHARF_PAD_HOLD` polls (default 1) then released for `WHARF_PAD_GAP` polls (default 12). Counting polls, not seconds, stops double steps and swallowed presses on a loaded host. It applies to the type 0 pad when no type 3 keystroke device exists (that was why it was dead).
- The `.lex` module fetch is not exercised yet: the 17559 dash never names `Dash.Social.lex`; modules load through XAM's demand-file layer (`XdfCacheItem` export 0x654, name lookup in the online manifest).

## v0.1.1 (2026-11-04)

- `WHARF_NIC_HTTPLOG=1` logs the first bytes of port-80 TCP payloads in both directions (dev aid, off by default).
- Writable host directory for `\Device\Harddisk0\Cache` (XAM stages TK_* temp files there).
- Verified end to end after a Live sign-in: `sap/online/system.online.manifest.<SOMRevision>` is downloaded from x360-som, passes XAM verification (container and body magic, SHA1, revision) and is stored; the refresh thread then exits 0. The `.lex` module fetch is lazy and not yet exercised. The scripted `pad` file input is not available in this build.

## v0.1.0 (2026-11-04)

First tagged Wharf release (Xbox 360 emulator fork of Xenia Edge, real 17559 dash).

- Mount a writable host directory (storage root `sap`) at `\Device\Harddisk0\SystemAuxPartition`, the target of XAM's `\sap` link, so the online module manifest can be stored at `\sap\online`.
- real_xam: a helper thread calls XAM export 0x65A (`XampDemandUpdateRefreshManifestDuringLogon`, 0x8168BD30) every 15 s once app 0xFE exists, until `sap/online` exists. Needs the Live config (SOMRevision, UpdateUriRoot1), so it only succeeds after a sign-in. Disable with `WHARF_NOSOMREFRESH=1`.
- Log the exit code of real_xam helper threads (`XThread '...' exit code`), which showed the refresh failing with 8007065B before sign-in and D000003A (path not found) without the SystemAuxPartition mount.
