# Evidence: wharf

## Online stack (verified with the pre-port WIP build, re-verification pending)

- 2026-10-16: the dashboard's Test Xbox Live Connection passed against OpenPak's
  Xbox 360 services (Network, Internet and Xbox Live connected), and MACS/XEAS/XETGS
  authenticated on the first attempt each.
- 2026-10-18/19: sign-in completed through Download Profile to presence (a Switch
  showed the 360 user online) and the "Downloading your game info" REST recovery.
- 2026-10-20: profile text sync (motto/bio/name/location) both directions;
  per-user download queues verified up to the download step.
- 2026-10-23: Games on Demand launch from stock My Games (GoD packaged Aurora).

The online stack (virtual NIC, real-XAM bring-up, system UI overlay) was ported
from the WIP branch to `wharf` with the temporary diagnostics stripped; the runs
above have not been repeated on the ported tree yet.

## Not verified

A completed Xbox Live sign-in on the ported tree, any retail game online, any
retail console against the same services, and any performance or compatibility
claim. At last check, HOME content from Xbox Live showed "temporarily unavailable".
