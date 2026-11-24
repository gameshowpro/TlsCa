---
# An application page. The values are under https_guide; the sections below are merged into the shared guide by
# their headings. This example is shortened from Soundling's page and is not its real configuration.
https_guide:
  product: Soundling
  ui_name: console
  reason: >-
    The console runs in the browser on .NET WebAssembly, which browsers start only on a secure page: one loaded over
    HTTPS, or from `localhost`.
  http_port: 9096
  https_port: 9196
  name_pattern: <host>-soundling.local
  name_example: studio-pc-soundling.local
  gate: loopback
  allow_http_fallback: false
  allow_https_fallback: true
  own_certificate: true
  settings_prefix: Soundling
  storage:
    - where: Windows
      path: '%ProgramData%\GameshowPro\Soundling\tls'
    - where: Linux
      path: /var/lib/GameshowPro/Soundling/tls
  unverified:
    - iPhone and iPad
    - Android
---

# Open the console over HTTPS

<!-- repository-only -->
> This file holds the application's own part of the guide. The published page merges it with the shared guide.
<!-- /repository-only -->

Programs that use the API are not affected. The API stays on plain HTTP on port 9096.

## What to know

- **Private networks only.** Soundling serves only clients on private networks.

## Settings

| Setting | Effect |
| --- | --- |
| `Soundling__HttpsPort` | The HTTPS port. 9196 by default. `0` turns HTTPS off. |

## Ports for a second instance

A second instance on the same computer needs its own HTTP and HTTPS ports.

## If it does not work

Soundling shows a system finding when HTTPS is turned off or the stored identity cannot be used.
