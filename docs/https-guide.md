{# The shared HTTPS user guide for applications that use GameshowPro.TlsCa. This file is a Jinja2 template: render it
   with render_https_guide.py and an application's values file. See integrating-the-https-guide.md. Keep headings free
   of values, so that links to them stay the same in every application. #}
# {{ title }}

{{ product }} serves its {{ ui_name }} over HTTPS, so that browsers on other computers and phones can open it securely. Each {{ product }} installation creates its own small certificate authority (CA) the first time it starts, and issues its HTTPS certificate from it. You install that CA once on each computer or phone that opens the {{ ui_name }}. After that, the browser connects with no certificate warning.

{% if reason %}
{{ reason }}

{% endif %}
{% if sections.after_intro is defined %}
{{ sections.after_intro }}

{% endif %}
## Addresses

{% if sections.addresses is defined %}
{{ sections.addresses }}
{% elif single %}
| | Address |
| --- | --- |
| Certificate page | `{{ single.page_any }}` |
| Secure address | `{{ single.secure }}` |
{% if single.local_access %}
| On the {{ product }} {{ single.host_term }} itself | `{{ single.http_local }}` |
{% endif %}

In the certificate page's address, `<host>` is the {{ product }} {{ single.host_term }}'s name or IP address. The secure address uses a name that {{ product }} chooses: `{{ single.name_pattern }}`, for example `{{ single.secure_example }}`. The certificate page shows the exact secure address.
{% else %}
| Build | Certificate page | Secure address |{% if builds | selectattr('local_access') | list %} On the device itself |{% endif %}

| --- | --- | --- |{% if builds | selectattr('local_access') | list %} --- |{% endif %}

{% for b in builds %}
| {{ b.name }} | `{{ b.page_any }}` | `{{ b.secure }}` |{% if builds | selectattr('local_access') | list %} {% if b.local_access %}`{{ b.http_local }}`{% else %}Not available{% endif %} |{% endif %}

{% endfor %}

In the certificate page's address, `<host>` is the device's name or IP address. The secure address uses a name that {{ product }} chooses{% for b in builds %}{{ ";" if not loop.first else ":" }} for {{ b.name }}, `{{ b.name_pattern }}` (for example `{{ b.secure_example }}`){% endfor %}. The certificate page shows the exact secure address.
{% endif %}

{% if builds | selectattr('local_access') | list %}
On builds that can be opened locally, find the address for another computer by opening the certificate page on the computer running {{ product }}, using its `localhost` address. **Address for other computers** shows the secure address with a **Copy secure address** button. Share that address with computers that already trust the CA. Scan the QR code on a phone to open the plain-HTTP setup address first; the phone can install the CA before you choose **Open the app over HTTPS**. The secure address is shown as text on the host computer because that computer may not trust its own CA.

{% for b in builds if b.local_access %}
{% if single %}The block{% else %}For {{ b.name }}, the block{% endif %} also lists {% if b.allow_http_fallback %}plain-HTTP IP addresses{% else %}HTTPS IP addresses{% endif %} for the selected networks when available. If several are listed, use the address on the network shared with the other computer.{% if b.allow_http_fallback or b.allow_https_fallback %} Use one on networks where `.local` names do not resolve.{% else %} These addresses reach setup; opening the {{ ui_name }} still needs `.local` lookup.{% endif %}{% if not b.allow_http_fallback %} The browser shows a certificate-name warning for an HTTPS IP address.{% if b.allow_https_fallback %} After you accept it, the certificate page checks the `.local` address and offers **Continue on this address** if that check fails.{% endif %}{% endif %}
{% endfor %}
{% endif %}
{{ '\n' }}

## Set up a computer or phone

Do this once on each computer or phone that opens the {{ ui_name }}.

1. **Open the certificate page** from the table above.{% if builds | selectattr('http_redirects') | list %} Opening a plain-HTTP page from another computer takes you there too. The page remembers the path and query you opened, and offers **Open the app over HTTPS** for that page after the connection check succeeds. API requests are left alone.{% endif %}

2. **Check the fingerprint.** The page shows the CA's fingerprint. To be sure you are trusting the right device, compare it with one from a source you trust: the same page opened at the device itself, where that is possible, or your administrator.
3. **Download and install the certificate.** The page offers the right file for your system and lists the steps. In short:

    | System | What to do |
    | --- | --- |
    | Windows | Open the downloaded file, choose **Install Certificate**, and place it in **Trusted Root Certification Authorities**. |
    | macOS | Add the file to the **System** keychain in Keychain Access, open it, and set it to **Always Trust**. |
    | iPhone and iPad | Download the profile in Safari, install it in **Settings**, then turn on full trust under **General**, **About**, **Certificate Trust Settings**. |
    | Android | Download the certificate. On Android 11 or later, do not open it from the download notification: open **Settings**, search for **Install a certificate**, choose **CA certificate**, tap **Install anyway**, and pick the downloaded file. |
    | Linux | Add the file to the system's trusted certificates, and import it into Chrome or Firefox, which keep their own lists. |

4. **Open the app over HTTPS.** After installing the CA, use this link on the certificate page. A successful connection check does not prove that the CA is installed: Firefox and other browsers may allow a certificate exception. Downloads and installation steps stay visible, and the page does not forward you automatically.

Later visits need only the secure address. Bookmark it.

If the connection check times out, check name resolution, network access, and the HTTPS TCP port in the device firewall. The page shows the port it checked and offers **Connection troubleshooting** and **Retry connection check**. A timeout does not identify the cause, and installing a certificate cannot open a blocked port. If the browser shows a certificate warning, install the certificate as described above. Other connection failures may involve name resolution, a blocked port, certificate trust, or browser restrictions. A different certificate identity or an unexpected response needs investigation before continuing; session fallback actions are not offered for those results.{% if builds | selectattr('allow_http_fallback') | list %} {% if single or (builds | rejectattr('allow_http_fallback') | list | length == 0) %}A{% else %}On {{ builds | selectattr('allow_http_fallback') | map(attribute='name') | join(' and ') }}, a{% endif %} secondary **Continue over HTTP** link lets you use the original page without encryption for this browser session. This can help when `.local` names cannot be found.{% endif %}{% if builds | selectattr('allow_https_fallback') | list %} {% if single or (builds | rejectattr('allow_https_fallback') | list | length == 0) %}If you opened{% else %}On {{ builds | selectattr('allow_https_fallback') | map(attribute='name') | join(' and ') }}, if you opened{% endif %} the certificate page through HTTPS by IP or another name, **Continue on this address** lets you stay on that HTTPS address for this browser session after the `.local` check fails. The browser's certificate-name warning still appears before the page opens; this choice cannot remove it.{% endif %}{% if (builds | selectattr('allow_http_fallback') | list) or (builds | selectattr('allow_https_fallback') | list) %} Use the app's certificate-page link to return and finish setup later. Closing the browser normally ends a session choice, although browsers that restore session cookies may keep it.{% endif %}

{% for b in builds if not b.allow_http_fallback and b.allow_https_fallback %}
{% if single %}If you reached{% else %}For {{ b.name }}, if you reached{% endif %} the certificate page over plain HTTP and the check fails, **Open this address over HTTPS** takes you to setup on the same host using the HTTPS port. The page shows that address and explains the browser's certificate-name warning. After accepting the warning, use **Continue on this address** if the check still fails. Your original path and query are kept. This link is not shown on `localhost`.

{% endfor %}
{% if sections.setup is defined %}
{{ sections.setup }}

{% endif %}

## What to know

- **The certificate is valid for one name only.** It works for the secure address in the table and for nothing else: not the bare computer name, not an IP address, and not `localhost`. An address such as `https://192.168.1.20{{ ":" ~ builds[0].https_port if builds[0].https_port != 443 else "" }}/` shows a certificate warning even after the CA is installed. Use the `.local` name when your computer can find it. If you continue past a warning at another HTTPS name, the certificate page checks the matching `.local` name before offering a link with the same path and query; it cannot prevent that first warning. `localhost` is left alone.
- **The CA cannot be misused for other sites.** It is restricted to that one name, so it cannot vouch for a bank, a mail server or any other address, even if someone stole its key. You install only the public certificate; no private key ever leaves {{ product }}.
- **The warning-free address needs `.local` lookup.** Windows 10 and later, macOS, iPhone, iPad and most Linux desktops can find `.local` names. Android can from version 12. Some Linux systems need `avahi-daemon` and `libnss-mdns`. The lookup uses mDNS (UDP port 5353, multicast), so it fails across routers, on guest Wi-Fi that isolates devices from each other, and through a firewall that blocks multicast.{% if builds | selectattr('allow_https_fallback') | list %} On builds that offer **Continue on this address**, HTTPS by IP can still work after you accept the browser's certificate-name warning.{% endif %}{{ '\n' }}
- **Firewall and network selection.** The {{ product }} {{ single.host_term if single else 'device' }} must accept connections from your network on {% if single %}TCP ports {{ single.http_port }} and {{ single.https_port }}{% else %}the TCP ports in the table{% endif %}, and mDNS on UDP port 5353.{% if links.firewall is defined %} See [firewall settings]({{ links.firewall }}).{% endif %} If the app is configured to listen on selected networks, use an address on one of those networks; mDNS advertisement scopes alone do not limit which addresses accept connections.

- **Firefox keeps its own list of trusted certificates.** Import the file into Firefox as well (**Settings**, **Privacy & Security**, **View Certificates**, **Authorities**), or on Windows turn on `security.enterprise_roots.enabled` in `about:config`.
- **The clock matters.** A computer or phone whose date is wrong may reject the certificate as not yet valid or expired.
{% if unverified %}
- **Not yet verified:** {{ unverified | join(", ") }}. The steps for these follow each system's documentation and have not been tried with {{ product }}. Report what you find.
{% endif %}
{% if sections.notes is defined %}
{{ sections.notes }}
{% endif %}

## Renewal and reset

{% set renewing = builds | selectattr('auto_renew') | list %}
{% set manual = builds | rejectattr('auto_renew') | list %}
{% set renewing_names = renewing | map(attribute='name') | list %}
{% set manual_names = manual | map(attribute='name') | list %}
{% if not manual %}
{{ product }} renews its HTTPS certificate by itself when fewer than {{ renew_days }} days of its validity remain. Computers and phones that already trust the CA keep working, and nobody has to do anything.
{% elif not renewing %}
The HTTPS certificate must be renewed before it expires. The certificate page shows when that is and has a **Renew certificate** button. Computers and phones that already trust the CA keep working after a renewal.
{% else %}
For the {{ (renewing_names[:-1] | join(", ") ~ " and " if renewing_names | length > 1 else "") ~ renewing_names[-1] }}, {{ product }} renews its HTTPS certificate by itself when fewer than {{ renew_days }} days of its validity remain. Computers and phones that already trust the CA keep working, and nobody has to do anything.

For the {{ (manual_names[:-1] | join(", ") ~ " and " if manual_names | length > 1 else "") ~ manual_names[-1] }}, the HTTPS certificate must be renewed before it expires. The certificate page shows when that is and has a **Renew certificate** button. Computers and phones that already trust the CA keep working after a renewal.
{% endif %}

A **reset** creates a completely new CA. Every computer and phone must then install the new certificate, and should remove the old one. The certificate page shows the old one's fingerprint as **Previous fingerprint** so you can tell which to remove. Reset only when you must: when the key may have been exposed, or to adopt a new name after a rename.

The **Renew certificate** and **Reset identity** buttons are on the certificate page. They are refused unless you show that you are at the device:

{% for gate in gates %}
{% set these = builds | selectattr('gate', 'equalto', gate) | list %}
{% set who = "" if single else " (" ~ (these | map(attribute='name') | join(", ")) ~ ")" %}
{% if gate == "loopback" %}
{% if these | selectattr('local_access') | list %}
- **On the computer itself{{ who }}.** Open the certificate page on the {{ product }} computer with a `localhost` address: `{{ these[0].page_local }}`. The buttons are refused from anywhere else on the network. On a computer with no screen, reach the page through an SSH tunnel (`ssh -L {{ these[0].http_port }}:127.0.0.1:{{ these[0].http_port }} <host>`, then open the same `localhost` address on your own computer), or run this on the computer itself, with `reset` in place of `renew` for a reset:

    ```sh
    curl -X POST -H "Content-Type: application/json" -d '{}' {{ these[0].page_local }}renew
    ```

{% else %}
- **On the device itself{{ who }}.** The buttons are refused from anywhere else on the network, and the device has no browser. Reach the page through an SSH tunnel (`ssh -L {{ these[0].http_port }}:127.0.0.1:{{ these[0].http_port }} <host>`, then open `{{ these[0].page_local }}` on your own computer), or run this on the device itself, with `reset` in place of `renew` for a reset:

    ```sh
    curl -X POST -H "Content-Type: application/json" -d '{}' {{ these[0].page_local }}renew
    ```

{% endif %}
{% elif gate == "boot" %}
- **After a power-up{{ who }}.** Switch the device off and on again, then press the button on the page within 5 minutes. A restart from software does not count.
{% else %}
- **With the device's button{{ who }}.** Press the button on the device, then press the button on the page within 60 seconds.
{% endif %}
{% endfor %}

A device that can take a certificate from your own authority shows one more section on the certificate page, **Your own certificate**. It lists which certificate the device serves and its names, and lets you upload a certificate with its private key (over HTTPS only), create a signing request and upload the signed certificate (which also works over plain HTTP), or remove your certificate. These changes use the same protection as Renew and Reset; where the device reports how long its five-minute window after power-up stays open, the page counts it down and disables the buttons when it ends. The page recommends the signing request first (the device's key is an elliptic-curve key) and warns that an uploaded RSA key makes every secure connection slower to set up. The section does not appear on devices that do not report this ability.

## If the device is renamed, or two devices share a name

- **Renamed.** The secure address keeps the old name until you reset, and keeps working. The certificate page tells you when the name no longer matches. A reset adopts the new name.
- **Two devices with the same name.** If another device on the network answers to the same `.local` name, the secure address may reach the wrong one, and the certificate page shows a warning. {{ product }} does not rename itself, because the certificate would no longer match. Remove or rename the other device, or rename this one and reset.

## Remove the certificate from a computer or phone

Remove the CA when a computer or phone no longer needs the {{ ui_name }}, and remove the old CA after a reset. It is listed as **GameshowPro Device CA** followed by the device name. Check the fingerprint when several are installed.

| System | Where |
| --- | --- |
| Windows | **Manage computer certificates** (or **Manage user certificates**), **Trusted Root Certification Authorities**, **Certificates**. |
| macOS | Keychain Access, **System** keychain. |
| iPhone and iPad | **Settings**, **General**, **VPN & Device Management**: remove the profile. |
| Android | **Settings**, search for **Trusted credentials**, **User** tab. |
| Linux | Delete the file you copied and run the same update command again. Remove it from Chrome and Firefox too. |

{% set stored = builds | selectattr('storage') | list %}
{% if stored %}
## Where the keys are kept

{{ product }} keeps the CA and its private keys here:

{% for b in stored %}
{% for place in b.storage %}
- {% if not single %}{{ b.name }}{% if place.where %}, {% endif %}{% endif %}{% if place.where %}{{ place.where }}{% endif %}{% if place.where or not single %}: {% endif %}`{{ place.path }}`
{% endfor %}
{% endfor %}

**This folder holds private keys.** Do not copy it into a backup, an archive, a support bundle or a shared drive. If it is lost or deleted, {{ product }} creates a new CA the next time it starts, and every computer and phone must install the new certificate, exactly as after a reset.

{# 'keys' in sections, not sections.keys is defined: Jinja falls back to the dictionary's own keys method. #}
{% if 'keys' in sections %}
{{ sections['keys'] }}

{% endif %}
{% endif %}
{% set own = builds | selectattr('own_certificate') | list %}
{% if own or sections.own_certificate is defined %}
## Use your own certificate

{% if own %}
{% set own_names = own | map(attribute='name') | list %}
If your organization issues certificates, or you have one from a public authority, {{ product }} can serve its {{ ui_name }} with that certificate instead of its own CA.{% if not single and own | length < builds | length %} This applies to the {{ (own_names[:-1] | join(", ") ~ " and " if own_names | length > 1 else "") ~ own_names[-1] }}.{% endif %}


| Setting | Meaning |
| --- | --- |
| `{{ settings_prefix }}__CertificatePath` | The certificate file: a PFX (PKCS #12) file, or a PEM file that holds the certificate followed by any intermediate certificates. |
| `{{ settings_prefix }}__CertificateKeyPath` | The private key file, when the certificate is a PEM file and its key is in a separate file. |
| `{{ settings_prefix }}__CertificatePassword` | The password of the PFX file or of an encrypted key file. Leave it out when there is none. |

{% if links.settings is defined %}See [how to change settings]({{ links.settings }}). {% endif %}The account that {{ product }} runs as must be able to read the files. Restart {{ product }} after changing these settings.

With your own certificate:

- **The address is the name in your certificate**, on the same HTTPS port: `{{ _origin_own }}`. Your network's DNS must lead that name to the {{ product }} {{ own[0].host_term }}. The `.local` secure address is no longer offered.
- **Plain-HTTP page visits use HTTPS** when the host matches a DNS name covered by your certificate. Other names, IP addresses and `localhost` are left alone.
- **There is nothing to install** on computers and phones that already trust whoever issued the certificate. The certificate page shows a short notice in place of the downloads, and has no **Renew certificate** or **Reset identity** button.
- **On Windows, intermediate certificates must be installed.** If your certificate was issued through an intermediate authority, install that authority's certificate in **Intermediate Certification Authorities** on the {{ product }} computer (**Manage computer certificates**). Windows sends only what it finds there; {{ product }} adds nothing to the certificate stores. On Linux the intermediates in the file are sent.
- **Renewal is yours.** Replace the files before the certificate expires. {{ product }} starts using the new files by itself, with no restart, and its log warns from 30 days before the expiry.
- **A certificate that cannot be loaded stops HTTPS** until the files are corrected. {{ product }} does not fall back to its own CA, because that would silently change what browsers must trust. The log says what is wrong.
- **To return to {{ product }}'s own CA**, remove the settings and restart. The CA is kept, so computers and phones that installed it earlier still trust it.

{% endif %}
{% if sections.own_certificate is defined %}
{{ sections.own_certificate }}

{% endif %}
{% endif %}
{% if sections.settings is defined %}
## Settings

Application maintainers who configure Kestrel endpoints themselves can let TlsCa provide the certificate selector. Call `AddGameshowProTlsCa` before adding generated HTTPS endpoints, then compose the app's HTTPS defaults and TlsCa in one action:

```csharp
ITlsCaHttps tls = kestrel.ApplicationServices.GetRequiredService<ITlsCaHttps>();
kestrel.ConfigureHttpsDefaults(https =>
{
    // Apply the app's other HTTPS defaults here.
    tls.Configure(https);
});
```

Set `TlsCaOptions.AppOwnsListeners = true` (default false) when the app owns endpoint configuration. The library then adds no listeners in any mode; the app configures all HTTP and HTTPS endpoints itself. `HttpPort` and `HttpsPort` remain the app's actual ports for redirects and discovery. A `TlsCaMdnsScope` can carry the complete usable address set for one adapter; give publications sharing a host name the same set, and withdraw their handles before changing it. For fallback addresses shown by the certificate page, explicit scopes contribute every usable address.

`ITlsCaHttps.Configure` selects the current certificate for each handshake in built-in CA and own-certificate modes; it does nothing when TlsCa does not supply a certificate.

{{ sections.settings }}

{% endif %}
{% if sections.extra is defined %}
{{ sections.extra }}

{% endif %}
## If it does not work

| What you see | Likely cause |
| --- | --- |
| A certificate warning | The address is not the secure address from the table (an IP address or the bare name), the CA is not installed on this computer or phone, the browser is Firefox and has not been given the certificate, or {{ product }} was reset and now has a new CA (compare the fingerprint). |
| "Not valid yet" or "expired" | The date on this computer or phone is wrong{% if builds | rejectattr('auto_renew') | list %}, or the certificate needs renewing{% endif %}. |
| The `.local` name is not found | This computer or phone cannot look up `.local` names, or the network blocks mDNS. Check from a computer on the same network segment as {{ product }}. |
| Nothing opens at all | {{ product }} is not running, or a firewall blocks the ports in the table. |
| The secure address opens a different device | Two devices share the name. See above. |
| Renew or Reset is refused | You are not at the device. See [Renewal and reset](#renewal-and-reset). |

{% if sections.troubleshooting is defined %}
{{ sections.troubleshooting }}

{% endif %}
{% if links.troubleshooting is defined %}
See also [troubleshooting]({{ links.troubleshooting }}).

{% endif %}
{% if sections.end is defined %}
{{ sections.end }}
{% endif %}
