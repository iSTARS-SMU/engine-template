# vendor/ — bundled trustchain platform source

**Do not edit by hand.** These directories are rsynced from the trustchain
monorepo (`trustchain/contracts/` and `trustchain/sdk/python/`) by
`trustchain/scripts/sync-template-vendor.sh`.

What's here:
  * `vendor/contracts` — `trustchain-contracts` source (DTOs, events,
    scope matcher, signatures). Imported as `trustchain_contracts`.
  * `vendor/sdk`       — `trustchain-sdk` source (EngineApp, RunContext,
    MockContext, DevHarness, LLM client, CLI). Imported as `trustchain_sdk`.

Why vendor + not PyPI:
  trustchain-sdk is at 0.1-alpha; not published to PyPI yet. Bundling
  them here lets `pip install -e ./vendor/contracts -e './vendor/sdk[server]'`
  satisfy the pyproject dependency before pip needs an index. When
  the SDK migrates to PyPI, vendor/ gets deleted and pyproject deps
  resolve from the index automatically — no other code changes needed.

Upgrading:
  From the trustchain monorepo:
      bash trustchain/scripts/sync-template-vendor.sh
  This overwrites vendor/ with the current monorepo state. Commit the
  diff as one unit ("sync vendor").

For downstream engine repos (published via push-engine.sh):
  Those repos have their OWN vendor/ bundled by push-engine.sh at push
  time. They're independent of this one — each engine repo is
  self-contained.
