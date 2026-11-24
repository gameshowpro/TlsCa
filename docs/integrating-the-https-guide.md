# Put the HTTPS user guide into your application's documentation

Applications that use GameshowPro.TlsCa behave the same way for their users: a certificate page, one secure address, a CA to install once per computer or phone. `https-guide.md` explains that to end users once, for every application. Your application keeps one page of its own that holds its values and its own sections, and your documentation build merges that page with the guide.

This page is for whoever maintains an application's documentation. The guide itself is for end users.

## Files

| File | Purpose |
| --- | --- |
| `https-guide.md` | The guide: a Jinja2 template. Do not publish it as it is. |
| `render_https_guide.py` | Merges and renders. A Python module and a command-line tool. |
| `check_examples.py` | Renders every example and builds it with MkDocs. Run by the library's CI. |
| `examples/soundling.md` | Example application page: one build, its own sections. |
| `examples/triggergate.yaml` | Example values file: three builds with different ports. |

The renderer needs Python with Jinja2 and PyYAML. MkDocs installs both, so a documentation build already has them.

The examples illustrate the format. They are not either application's real configuration.

## The application page

Keep one committed page in your documentation, for example `docs/console-https.md`. It has two parts:

- **Front matter** with your values under `https_guide`. See [Values](#values).
- **Your own sections**, written as ordinary Markdown under the guide's headings. See [Your own sections](#your-own-sections).

```markdown
---
https_guide:
  product: Soundling
  ui_name: console
  http_port: 9096
  https_port: 9196
  name_pattern: <host>-soundling.local
  name_example: studio-pc-soundling.local
---

# Open the console over HTTPS

Programs that use the API are not affected. The API stays on plain HTTP on port 9096.

## Settings

| Setting | Effect |
| --- | --- |
| `Soundling__HttpsPort` | The HTTPS port. `0` turns HTTPS off. |
```

The page is a real file, so links to it from a README work on GitHub, the site's "edit this page" link opens the right file, and tools that check links against the repository find it. Read in the repository it shows only your application's part; the published page is the whole guide.

To tell repository readers where the whole guide is, wrap a note in these comments. It is removed from the published page:

```markdown
<!-- repository-only -->
> The [published page](https://example.com/console-https/) merges this file with the shared guide.
<!-- /repository-only -->
```

## Merge in the MkDocs build

Add a hook that merges every page that carries `https_guide` values:

```python
# scripts/docs/https_guide_hook.py
import sys
from pathlib import Path

TLSCA_DOCS = Path(__file__).resolve().parents[3] / "TlsCa" / "docs"  # See "Where the files come from".


def on_page_markdown(markdown, page, config, files):
    values = page.meta.get("https_guide")
    if values is None:
        return markdown
    if str(TLSCA_DOCS) not in sys.path:
        sys.path.insert(0, str(TLSCA_DOCS))
    from render_https_guide import merge_page

    return merge_page(values, markdown)
```

```yaml
# mkdocs.yml
hooks:
  - scripts/docs/https_guide_hook.py
```

Nothing is written to disk and nothing needs ignoring in Git. A missing or unknown value stops the build with a message that names it.

**Order among your hooks.** MkDocs runs hooks in the order listed. List this hook after any hook that rewrites Markdown for your own conventions, so that those conventions apply to your text and not to the shared guide. The guide puts the names of buttons and menus of Windows, macOS, iOS and Android in bold, for example **Settings**; a hook that decorates your application's labels wherever they appear in bold would otherwise decorate those.

## Without MkDocs

The command-line tool merges an application page into a complete Markdown file:

```sh
python render_https_guide.py docs/console-https.md --output site/console-https.md
```

With `--check` it writes nothing and fails when the output is missing or out of date, for a rendered copy that is committed.

## Values

Top-level values:

| Value | Required | Default | Meaning |
| --- | --- | --- | --- |
| `product` | Yes | | The application's name as users know it. |
| `title` | | `Secure access (HTTPS)` | The page's heading. In an application page, the first-level heading is the title. |
| `ui_name` | | `web page` | What the user opens, as a noun without "the": `console`, `web page`, `control panel`. |
| `reason` | | | One short paragraph on why this application needs HTTPS. Shown after the introduction. |
| `renew_days` | | `90` | Days before expiry at which renewal happens (`RenewWhenRemaining`). Applies to the builds that renew by themselves. |
| `settings_prefix` | With `own_certificate` | | The prefix of the application's settings as environment variables: `Soundling` gives `Soundling__CertificatePath`. It is the application's `TlsCaOptions.ConfigurationSection`. |
| `links.settings` | | | A link to your instructions for changing settings, relative to the page. |
| `links.firewall` | | | A link to your firewall instructions, relative to the page. |
| `links.troubleshooting` | | | A link to your troubleshooting section, relative to the page. |
| `unverified` | | | A list of systems you have not tried. The guide says so to the reader. |
| `heading_offset` | | `0` | Lowers every heading by this many levels, to embed the guide under a heading of your own. |
| `builds` | | | A list of builds. Leave it out when there is one build. See [Several builds](#several-builds). |

Values of a build. With one build, give them at the top level:

| Value | Required | Default | Meaning |
| --- | --- | --- | --- |
| `name` | With several builds | | The build's name as users know it: `Windows service`, `ESP32 board`. |
| `http_port` | Yes | | The plain-HTTP port that serves the certificate page (`TlsCaOptions.HttpPort`). |
| `https_port` | Yes | | The HTTPS port (`TlsCaOptions.HttpsPort`). |
| `name_pattern` | Yes | | The secure name with placeholders: `<host>-soundling.local`. |
| `name_example` | Yes | | A realistic example of it: `studio-pc-soundling.local`. |
| `host_term` | | `computer` | What the thing running the application is called: `computer`, `device`, `board`. |
| `gate` | | `loopback` | What allows Renew and Reset: `loopback` (opened on the computer itself), `boot` (within 5 minutes of a power-up) or `button` (within 60 seconds of pressing the device's button). It is the `gate` value in the application's `info.json`. |
| `auto_renew` | | `true` | Whether the build renews its certificate by itself. The .NET integration does; firmware with no clock cannot. The guide words the renewal section for each build. |
| `local_access` | | `true` | Whether a browser can run on the device itself and open `localhost`. Without it, the guide shows no `localhost` address for the build and, with the `loopback` gate, explains the SSH tunnel and `curl` only. |
| `http_redirects` | | `true` | Whether opening the plain HTTP address from another computer leads to the certificate page (`RedirectHttpRoot`). |
| `own_certificate` | | `false` | Whether the build can serve a certificate the user supplies through the `CertificatePath` settings. The .NET integration can. The guide then includes its "Use your own certificate" section. |
| `storage` | | | Where the keys are kept: a path, or a list of `where` and `path` pairs for several systems. Leave it out when users cannot reach the storage. |

Ports 80 and 443 are left out of the addresses the guide prints.

## Your own sections

In the application page, a second-level section is matched to the guide by its heading:

| Your heading | Where your text goes | Use it for |
| --- | --- | --- |
| (text before the first `##`) | After the introduction. | What HTTPS does not change, such as an API that stays on HTTP. |
| `## Addresses` | **Replaces** the generated address table. | An address table of your own, when the generated one does not fit. |
| `## Set up a computer or phone` | After the setup steps. | Other places your application shows the secure address, such as its log. |
| `## What to know` | At the end of that list. Write list items. | Facts about your application or its devices. |
| `## Where the keys are kept` | At the end of that section. Left out when no `storage` is given. | Who can read the folder, and old key material your application removes. |
| `## Use your own certificate` | At the end of that section. Without `own_certificate` on any build, your text is the whole section. | Another way your application takes a certificate, such as an upload on a device, or settings it honored before. |
| `## Settings` | As the "Settings" section, which the guide leaves out without it. | Setting names, turning HTTPS off. |
| `## If it does not work` | After the symptom table. | Your application's own symptoms, findings and log messages. |
| Any other `##` heading | As a whole section of its own, heading included, before "If it does not work". After it, when your page puts the section after `## If it does not work`. | Anything the guide has no place for. |

Your text is copied as it is. It is not treated as a template, so write your ports and names out. Use `###` for headings inside a section.

If you replace the address table, keep the terms the rest of the guide uses: "certificate page" and "secure address".

## Several builds

When an application ships builds with different ports, names or gates, list them under `builds`. Each build inherits any value it leaves out from the top level. The guide then prints one row per build in its address table, names the builds beside each way of allowing a reset, and lists each build's storage. `examples/triggergate.yaml` shows three builds.

If the builds differ so much that one page would confuse readers, keep one application page per build.

## Links into the guide

The guide's headings hold no values, so their anchors are the same in every application and stay the same between versions:

`#addresses`, `#set-up-a-computer-or-phone`, `#what-to-know`, `#renewal-and-reset`, `#if-the-device-is-renamed-or-two-devices-share-a-name`, `#remove-the-certificate-from-a-computer-or-phone`, `#where-the-keys-are-kept`, `#use-your-own-certificate`, `#settings`, `#if-it-does-not-work`.

On the published page all of them exist. In the repository, only the headings your page contains do, so a link to another one opens the top of the file there.

## What stays in your own documentation

The guide covers what every application shares. Keep these in your application page or elsewhere in your documentation:

- Installation, and how to open firewall ports. Link to it with `links.firewall`.
- Setting names and how to set them.
- Turning HTTPS off.
- Ways of supplying a certificate other than the library's settings.
- Anything about upgrading from an earlier version of your application.
- Messages in your application's own interface or log that point users to the guide.

## A values file instead of a page

The renderer also takes a YAML or JSON file of values, with custom sections as text under `sections`, and writes a complete page:

```sh
python render_https_guide.py docs/https-guide.yaml --output docs/generated/https.md
```

Use it when no committed page is wanted. Section names are `after_intro`, `addresses`, `setup`, `notes`, `keys`, `own_certificate`, `settings`, `extra`, `troubleshooting` and `end`. Each is text, or `{file: <path>}` relative to the values file, and is rendered as a template with the same values, so it can use `{{ product }}` or `{{ single.https_port }}`. The output starts with a comment saying it is generated. `examples/triggergate.yaml` is a values file.

## Where the files come from

The renderer and the guide must come from the same version of GameshowPro.TlsCa that the application uses, so that the page describes the certificate page the user actually sees.

The NuGet package carries this folder as `docs/`. Read it from the restored package, so that updating the package reference updates the guide:

1. Add `GeneratePathProperty="true"` to the application's `PackageReference` for `GameshowPro.TlsCa`. After a restore, the MSBuild property `PkgGameshowPro_TlsCa` holds the package's folder.
2. In the documentation build, ask MSBuild for it and add `docs`:

    ```python
    import subprocess

    folder = subprocess.run(
        ["dotnet", "msbuild", str(PROJECT), "-getProperty:PkgGameshowPro_TlsCa"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    TLSCA_DOCS = Path(folder) / "docs"
    ```

    `PROJECT` is the application project that references the package. The project must have been restored.

While an application references the library as a sibling checkout (a project reference), read `../TlsCa/docs` instead, as the hook above does. That works on a developer's computer and not in CI.

The library's CI checks that the package holds this folder. Reading it from a restored package, as in step 2, has not been exercised yet.

## Changing the guide

Change `https-guide.md` here, not an application's copy. Keep headings free of values. After a change, run the check, then render both examples and read the result:

```sh
python check_examples.py
python render_https_guide.py examples/soundling.md --output /tmp/soundling.md
python render_https_guide.py examples/triggergate.yaml --output /tmp/triggergate.md
```

When a heading changes, change `PAGE_HEADINGS` in the renderer and the tables on this page with it: application pages match on the heading text.

When the certificate page (`src/GameshowPro.TlsCa/wwwroot/management.html`) changes its wording, steps, button names or gate timings, change the guide to match.
