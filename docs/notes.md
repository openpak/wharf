# Notes: wharf

- The GPU shaders are globbed at CMake configure time: after adding a shader
  (e.g. under `src/xenia/gpu/shaders/`), re-run the configure step before
  building, or Ninja will not know about the new file.
- `xb build` defaults to a debug build and can exhaust memory at high
  parallelism; the working release build is
  `flock /tmp/openpak-build.lock nice -n 19 ninja -C build -f build-Release.ninja -j6 xenia_edge`.
- One emulator window at a time; one build at a time under the build lock.
- Temporary diagnostics (scripted pad, crash backchain, packet logs, `WHARF_*`
  environment switches) stay out of the tree; the reusable ones live in
  `scratch/wharf/` as patches, not commits.
