# Provenance: wharf

Where Wharf's kernel and hardware behaviour comes from when it is not a plain
upstream Xenia import. Sources are console and emulator behaviour and the
17559 system binaries (XAM, dash) only.

## Disc-only media check, protected flag 2 (2026-11-09)

Behaviour: `--modded_kernel_media_check_bypass` (default on) loads a title
whose XEX carries `XEX_IMAGE_XGD2_MEDIA_ONLY` (0x8) the way an XeUnshackle/RGH
kernel does, so Games on Demand copies of XGD2-only discs (iso2god, which does
not rewrite the XEX) run from My Games. Off, Wharf behaves like a stock kernel.

Evidence:

- XAM 17559 title start `FUN_8169ed78` reads the running XEX's security info:
  image flags (+0x10c) bit 0x8. At launch stage 1 (+0x388 == 1) it asks the
  disc object (vtable `0x815f8a28`) whether the disc is authenticated (+0x2c:
  field +0x4090) and if not calls +0xc(1), `0x816adb50`.
- `0x816adb50`: `XeKeysGetProtectedFlag(2)` == 0 returns success. Otherwise
  `ObReferenceObjectByName("\Device\CdRom0")`, then
  `IoSynchronousDeviceIoControlRequest(0x240a0)` with a 4-byte result: 1 passes,
  2 marks the disc authenticated and passes, 3 sets security stat 3 and fails,
  anything else (or a failed request) fails with C0053101/C0053102. The failure
  is the "Unsupported Disc" seen launching the Fable II GOTY GoD (4D5307F1).
- XeUnshackle patches one instruction in the kernel's `XexpLoadXexHeaders` so
  that `XexpVerifyMediaType` returns 1; it patches nothing in XAM. So on a
  modded console the XAM path above must already pass, i.e. protected flag 2
  is clear.
- Wharf had neither `XeKeysGetProtectedFlag` nor `XeKeysSetProtectedFlag`
  (undefined externs leave guest r3 as the argument, so flag 2 read as set).

Implementation: the protected flags are kernel state set through
`XeKeysSetProtectedFlag` and read by `XeKeysGetProtectedFlag`
(`xboxkrnl_crypt.cc`). The XEX loader (`UserModule::LoadContinue`) sets flag 2
for a media-only title executable only when the bypass is off, and clears it for
every other executable.

Inference, not observed: that the stock kernel's media verification is what
sets flag 2. No kernel binary was read; the claim rests on XeUnshackle
patching only that call while the XAM check above still passes on modded
hardware. Wharf emulates no DVD drive, so with the bypass off the disc check
fails, matching a stock console without the disc.

Regression check: with the bypass on, launch the Fable II GoD from signed-out
My Games; XAM must not show "Unsupported Disc" and must not call
`IoSynchronousDeviceIoControlRequest` 0x240a0 for it. With
`--modded_kernel_media_check_bypass=false` the same launch must show
"Unsupported Disc". XBLA titles (no 0x8 flag, e.g. Minecraft 584111F7) must
launch either way.

Verified 2026-11-09 (console A, signed out): Fable II GOTY GoD launches from My
Games and renders its intro with the bypass on; no 0x240a0 request is made. The
bypass-off half of the regression check has not been run yet.
