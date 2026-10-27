# Evidence: wharf

## Port verification (2026-10-27, `wharf` at 23542dec9)

The online stack (virtual NIC, real-XAM bring-up, system UI overlay) was ported
from the WIP branch with the temporary diagnostics stripped, and re-verified end
to end against the deployed services (screenshots in `scratch/wharf/shots/port-*`):

- Boot to HOME for an offline profile and a Live profile; avatars render and
  persist across restarts; gamer pictures render on the chooser and in the corner.
- Test Xbox Live Connection: Network, Internet and Xbox Live all Connected, every
  service line Up (KDC, NCSI, servicestatus, XEXDS).
- Live sign-in of an existing profile: MACS/XEAS/XETGS, WLID (nexus + login),
  presence icons and content fetch, no error codes.
- Social → native gamer card; Music → library → source picker; View Games →
  achievements list; Settings → System/Network, Preferences, Family (Content
  Controls), Profile screens all open natively.

## Earlier runs (pre-port WIP build)

- 2026-10-18/19: sign-in through Download Profile to presence (a Switch showed
  the 360 user online) and the "Downloading your game info" REST recovery.
- 2026-10-20: profile text sync (motto/bio/name/location) both directions;
  per-user download queues verified up to the download step.
- 2026-10-23: Games on Demand launch from stock My Games (GoD packaged Aurora).

## Known failures (2026-10-27)

- Library tiles (My Games, Recent, Collection, My Apps) fail with 8b050007,
  online and offline, with no network traffic. Eliminated: servers (no errors),
  URI params (bare `gameslibrary:` fails the same), poison content fixtures,
  the XAM online-module state machine (its check never executes at failure
  time). The native achievements list enumerates fine, so content enumeration
  works; the failure is in the manifest-URI launch path itself.
- The Settings Account/Privacy tiles do not render even when signed in to Live.
  Eliminated: the action names and the icons (known-good swaps of both still
  render nothing). The channel template renders 4 manifest slots; Settings
  authors 6. Needs a scrolling template or a restructure.
- The signed-out Profile tile fails locally with d000000f instead of offering
  sign-in (manifest UX gap, no network involved).
- "Join Xbox Live" cannot work: the sign-up client ships only in console flash.

## Not verified

Any retail game online, any retail console against the same services, the Download
Profile REST recovery on the ported tree (existing-profile sign-in works; the
recovery path is unchanged server-side since its 2026-10-19 verification), and
any performance or compatibility claim.
