# Distribution: builds, signing, antivirus, permissions

Status: v1 (Phase 1.5, 2026-10-17). Workflows: `.github/workflows/ci.yml`,
`.github/workflows/release.yml`.

## 1. What the release pipeline produces

| Platform | Built on (native runner) | Artifacts |
|---|---|---|
| macOS | `macos-15` (arm64) + `macos-15-intel` (x86_64), merged with `lipo` | `Remora-<ver>-macos-universal.dmg` (Remora.app containing host + viewer) |
| Windows | `windows-2025` (x86_64, MSVC) | `Remora-<ver>-windows-x86_64.msi`, `remora-<ver>-windows-x86_64.zip` (portable) |
| Linux (glibc) | `ubuntu-22.04` — oldest supported, so binaries run on newer distros | `.deb`, `.rpm`, `Remora-<ver>-linux-x86_64.AppImage`, `.tar.gz` |
| Linux (musl, static) | `ubuntu-22.04` | `remora-signal-<ver>-linux-x86_64-musl.tar.gz` — **signal server only** (see §1.1) |
| all | — | `SHA256SUMS` covering every file |

**Triggers**
* `git tag v0.1.0 && git push origin v0.1.0` → full release with auto-generated
  notes. The tag must equal `version` in the root `Cargo.toml`, or the run fails.
  Tags with a suffix (`v0.1.0-rc.1`) become pre-releases.
* **Actions → Release → Run workflow** on any branch/commit → "nightly" build,
  version `0.0.1-nightly.<date>.<sha>`. Installers are attached to the run as
  artifacts. Tick *publish_nightly* to also replace the rolling `nightly`
  pre-release.

**Verify a download:** `shasum -a 256 -c SHA256SUMS --ignore-missing` (macOS/Linux)
or `Get-FileHash <file> -Algorithm SHA256` (Windows) and compare.

### 1.1 Decisions and limits

* **musl static build = remora-signal only.** A fully static musl binary cannot
  `dlopen` GPU drivers (Vulkan, VAAPI), so it cannot be the GUI host/viewer once
  those use the GPU. For the server, a static binary is ideal (runs anywhere,
  Docker `FROM scratch`). For the apps, maximum Linux compatibility comes from
  the glibc build on the oldest Ubuntu plus the AppImage.
* **Tagged releases build without cache** (no cache → no cache poisoning).
  Nightly builds and CI use `Swatinem/rust-cache`.
* **Pinned tools.** Third-party actions are pinned by commit SHA; `appimagetool`
  1.9.1 and its type2 runtime (20251108) are pinned by SHA-256; WiX Toolset is
  pinned to 5.0.2 (v6 requires accepting the Open Source Maintenance Fee EULA; revisit later).
* **Runner labels.** `macos-15-intel` is GitHub's last Intel macOS image. When
  GitHub retires it, switch the x86_64 slice to cross-compiling on arm64
  (`rustup target add x86_64-apple-darwin` works fine on Apple Silicon) and drop
  the native smoke test for that slice.
* **Not yet exercised on GitHub.** The workflows pass `actionlint` and `zizmor`
  (0 findings, auditor persona), and the macOS DMG, .deb and .rpm steps were
  run locally — but the Windows MSI (WiX) and AppImage steps have only run
  once the repository is pushed. Expect small fixes on the first run.

## 2. macOS: signing, notarization and the Screen Recording permission

### Why signing matters for Remora specifically

macOS stores privacy permissions (**Screen Recording**, **Accessibility**)
in TCC, keyed to the app's **code signature identity**:

* **Ad-hoc signed** (no certificate, what we ship today): the identity is the
  binary's hash. **Every update looks like a new app** → the user must grant
  Screen Recording and Accessibility again after each update.
* **Self-signed dev identity**: stable across rebuilds on *your* machine
  (Phase 2 adds `scripts/macos/dev-identity.sh`), useless for distribution.
* **Developer ID signed + notarized**: stable for every user, no Gatekeeper
  warning, permissions survive updates. Requires the Apple Developer Program.
* Note: running a binary from Terminal attributes permissions to *Terminal*,
  so `cargo run` during development doesn't re-prompt.
* Newer macOS versions periodically re-confirm screen-recording permission for
  apps using it; Apple offers a persistent-capture entitlement for remote-desktop
  apps, which requires a paid account and Apple's approval.

### Installing an unsigned build (until we sign)

Open the DMG and drag Remora to Applications. On first launch macOS says it
"cannot verify the developer". Open **System Settings → Privacy & Security**,
scroll down, click **Open Anyway**. (Terminal alternative:
`xattr -dr com.apple.quarantine /Applications/Remora.app`.)

### Adding Apple signing later — step by step

1. **Join the Apple Developer Program** (developer.apple.com/programs, USD 99/year).
2. **Create a "Developer ID Application" certificate.** Only the account holder
   can. Easiest: Xcode → Settings → Accounts → select team → *Manage
   Certificates…* → **+** → *Developer ID Application*.
3. **Export it as .p12.** Keychain Access → *My Certificates* → right-click
   "Developer ID Application: …" → *Export…* → `.p12`, choose a strong password.
4. **Find the identity string:** `security find-identity -v -p codesigning`
   → e.g. `Developer ID Application: Your Name (ABCDE12345)`.
5. **Create an App Store Connect API key** (for notarization):
   appstoreconnect.apple.com → *Users and Access* → *Integrations* →
   *App Store Connect API* → *Team Keys* → **+** (access: *Developer*).
   Download `AuthKey_XXXXXXXXXX.p8` — **it can be downloaded only once**.
   Note the **Key ID** and the **Issuer ID** shown on that page.
6. **Pick the final bundle ID** before the first signed release (TCC grants
   are tied to it). Today: `io.github.remora.Remora`; change via the
   `REMORA_BUNDLE_ID` env var in `release.yml` / `scripts/macos/bundle.sh`.
7. **Add the secrets** (see §4 for where):

| Secret | Value |
|---|---|
| `MACOS_CERTIFICATE_P12_BASE64` | `base64 -i cert.p12 \| pbcopy`, paste |
| `MACOS_CERTIFICATE_PASSWORD` | the .p12 export password |
| `MACOS_SIGNING_IDENTITY` | the identity string from step 4 |
| `APPLE_API_KEY_P8_BASE64` | `base64 -i AuthKey_XXXXXXXXXX.p8 \| pbcopy` |
| `APPLE_API_KEY_ID` | Key ID (10 characters) |
| `APPLE_API_ISSUER_ID` | Issuer ID (UUID) |

8. Run the Release workflow. The log should say "Signing with identity…",
   then notarytool "Accepted", then stapler "The staple and validate action worked!".
   Then delete the local `.p12` and `.p8` copies you no longer need.

## 3. Windows: signing, SmartScreen and antivirus

### 3.1 Antivirus WILL flag Remora

A program that captures the screen, injects keyboard/mouse input and talks to
the internet is, behaviourally, what a **remote-access trojan (RAT)** does.
Heuristic and ML-based antivirus engines will flag unsigned Remora builds —
sometimes as `RemoteAdmin`, `PUA`/`PUP` (potentially unwanted) or generic
`Trojan:Win32/…`. Even AnyDesk and TeamViewer are classified as remote-admin
PUA by some vendors. **This cannot be avoided completely; it can be reduced.**

What reduces it:

1. **Code signing.** Engines and SmartScreen build *reputation per signing
   certificate*. Unsigned binaries have no reputation and every new build is a
   new unknown file. With a certificate, reputation accumulates across releases.
2. **Behaving unlike malware** — already Remora's design: visible window and
   tray indicator, explicit accept prompt, no silent install, no hidden
   persistence, no process injection, no packers/obfuscation, honest version
   info.
3. **Consistent, reproducible releases** from CI (same publisher, same
   structure every time).
4. **False-positive reports** (below) after each release.

### 3.2 Per-release VirusTotal check (manual for now)

1. After a release is published, upload the `.msi`, the `.zip` and the
   `.exe` files inside it to https://www.virustotal.com (or `vt scan file <path>`
   with the VirusTotal CLI). Uploads become available to security vendors —
   fine for public releases, never do it for private builds.
2. Record the detection ratio in the release notes (e.g. "VirusTotal: 2/72").
3. For each detection, submit a false-positive report to the vendor:

| Vendor | Where to report (verify — vendors move these pages) |
|---|---|
| Microsoft Defender | https://www.microsoft.com/en-us/wdsi/filesubmission (choose *Software developer*) |
| Avast / AVG | https://www.avast.com/false-positive-file-form.php |
| Kaspersky | https://opentip.kaspersky.com (upload, then *Request reanalysis*) |
| ESET | email the file (zipped, password `infected`) to samples@eset.com, subject "False positive" |
| Bitdefender | https://www.bitdefender.com/consumer/support/answer/29358/ |
| Norton (Gen Digital) | https://submit.norton.com |
| Sophos | https://support.sophos.com/support/s/filesubmission |

Automating the VirusTotal upload (API key as a secret) is a possible later step.

### 3.3 Installing an unsigned build

SmartScreen shows "Windows protected your PC" → **More info** → **Run anyway**.
If antivirus quarantines it, verify the SHA-256 against `SHA256SUMS` first, then
add an exclusion only if it matches.

### 3.4 Adding Windows signing later — step by step

> **Important:** since June 2023, publicly trusted code-signing certificates
> must keep their private key on hardware (HSM / USB token). New OV/EV
> certificates are therefore generally **not** available as an exportable
> `.pfx`. For CI, use **Azure Artifact Signing** (Microsoft's cloud signing
> service, formerly "Trusted Signing"), or a CA's cloud-HSM service. The PFX
> path in the workflow exists for older certificates and test certificates.

**Option A — Azure Artifact Signing (recommended)**

1. Check current eligibility and pricing on Microsoft's Artifact Signing page
   (it has at times been limited to organizations, or to individuals in certain
   countries; the Basic tier has been around USD 10/month).
2. In the Azure portal: create an **Artifact Signing account** (note its
   region **endpoint**, e.g. `https://eus.codesigning.azure.net/`).
3. Complete **identity validation** (individual or organization).
4. Create a **certificate profile** of type *Public Trust*; note its name.
5. **Microsoft Entra ID → App registrations → New registration** (e.g.
   `remora-ci-signing`). Note the **Directory (tenant) ID** and **Application
   (client) ID**. Under *Certificates & secrets* create a **client secret**
   (note its expiry and set a reminder).
6. On the Artifact Signing account → *Access control (IAM)* → add role
   assignment **"Artifact Signing Certificate Profile Signer"** (older name:
   "Trusted Signing Certificate Profile Signer") → assign to the app
   registration.
7. Add the secrets:

| Secret | Value |
|---|---|
| `AZURE_TENANT_ID` | Directory (tenant) ID |
| `AZURE_CLIENT_ID` | Application (client) ID |
| `AZURE_CLIENT_SECRET` | the client secret value |
| `AZURE_SIGNING_ENDPOINT` | account endpoint URL |
| `AZURE_SIGNING_ACCOUNT` | Artifact Signing account name |
| `AZURE_CERTIFICATE_PROFILE` | certificate profile name |

   Later improvement: replace the client secret with GitHub OIDC (federated
   credential) so no long-lived secret exists.

**Option B — existing exportable certificate (.pfx)**

| Secret | Value |
|---|---|
| `WINDOWS_CERTIFICATE_PFX_BASE64` | `[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx"))` |
| `WINDOWS_CERTIFICATE_PASSWORD` | the .pfx password |

If `AZURE_CLIENT_ID` is set, Option A is used; otherwise Option B if its
secret is set; otherwise the build is unsigned with a warning.

## 4. Where to put the secrets (do this once)

The signing jobs run in a GitHub **Environment** called `release` (created
automatically on the first run). Environments let you restrict who can use the
secrets:

1. Repository → **Settings → Environments → release**.
2. *Deployment branches and tags* → **Selected branches and tags** → add tag
   rule `v*` and branch `main` (nightlies are dispatched from main).
3. Optional: *Required reviewers* → yourself, so every signing run needs a click.
4. *Environment secrets* → **Add secret** for each secret above. (With the
   `gh` CLI: `gh secret set MACOS_CERTIFICATE_PASSWORD --env release`, which
   prompts for the value so it never lands in shell history.)

Repository-level secrets (Settings → Secrets and variables → Actions) also
work, but don't get the branch/tag restriction.

Security notes: secrets are only exposed to the two signing jobs, never to
`pull_request` workflows; the release workflow doesn't run on pull requests at
all; keychains/PFX/P8 files are created in `$RUNNER_TEMP` and deleted.

## 5. Other distribution notes

* **OpenH264 patents.** Cisco's H.264 patent license covers only Cisco's
  prebuilt OpenH264 binaries, not copies compiled from source (which the
  `openh264` crate does). Remora prefers OS/hardware encoders; for the software
  fallback we'll evaluate downloading Cisco's binary at runtime, as Firefox
  does, before v0.1. Not legal advice.
* **Linux packages** list shared-library dependencies automatically (`$auto`
  in cargo-deb); the AppImage bundles nothing but our binaries for now.
