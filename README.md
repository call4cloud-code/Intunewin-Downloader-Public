# IntuneWin Downloader

IntuneWin Downloader is a Windows troubleshooting and inspection tool for Microsoft Intune.

The tool can:

* Load assigned Win32 apps from the local Company Portal catalog
* Download and decrypt IntuneWin packages through the local Intune client side flow
* Extract package content and export metadata
* Run local install tests for troubleshooting
* Pull assigned Remediations through the IME HealthScripts GetScript flow
* Decode detect.ps1 and remediate.ps1 directly from the service response
* Export raw remediation policy JSON and signature metadata

The goal is simple.

Recover and inspect the same content the current device and user are already allowed to receive through Intune, without needing Graph permissions, app registrations, or direct service side access.

---

# Features

## Win32 apps

The Win32 apps section can:

1. Load available Win32 apps from the Company Portal catalog
2. Show app icon, name, version, publisher, intent, and install state
3. Download one or multiple selected apps in parallel
4. Retrieve the correct committedContentVersion before download
5. Download encrypted IntuneWin content through the local SideCar flow
6. Decrypt and extract the package locally
7. Export useful metadata next to the extracted content
8. Parse Package.xml metadata when available
9. Build install and uninstall commands from the package metadata
10. Run local install tests
11. Run silent install tests as SYSTEM through a temporary scheduled task
12. Optionally remove silent switches for visible installer UI testing
13. Export logs for troubleshooting

## Remediations

The Remediations section uses the IME HealthScripts GetScript flow.

The tool:

1. Acquires the same local SideCar WAM token used by the Intune client flow
2. Uses the local Intune MDM certificate
3. Uses the HealthScripts workload through the IME AgentCommon path
4. Pulls assigned remediation policies directly from the service response
5. Decodes PolicyBody into detect.ps1
6. Decodes RemediationScript into remediate.ps1
7. Exports raw remediation policy JSON
8. Exports the ContentSignature metadata and signing information
9. Opens remediation scripts directly inside the app
10. Supports downloading all assigned remediations or filtering by remediation policy id

No Microsoft Graph permissions or custom app registrations are required.

---

# What the tool does not do

The tool only accesses content that the current device and current user are already allowed to receive through the normal Intune client side flow.

The tool does not:

* Grant access to apps or remediations that are not assigned
* Modify Intune assignments
* Change tenant configuration
* Replace the Intune Management Extension
* Emulate the complete Intune install engine
* Fully reproduce ESP behavior, dependency handling, retry logic, supersedence, or reporting

Local install testing is only intended as a troubleshooting helper.

---

# Intended use

This tool is intended for troubleshooting and lab scenarios such as:

1. The original Win32 app source files are no longer available
2. You want to inspect extracted package content
3. You want to validate installer commands
4. You want to test installers locally
5. You want to inspect remediation scripts assigned to a device
6. You want to compare remediation versions and content
7. You want to review remediation detect and remediation logic without digging through IMECache manually
8. You want to collect metadata and logs for troubleshooting

Use it on test devices first.

---

# Requirements

* Windows device already enrolled into Intune
* .NET 8 runtime installed
* Local Intune enrollment must be healthy
* Company Portal and IME related components must be functional

Some functionality depends on:

* Local Intune certificates
* WAM token availability
* Company Portal catalog state
* IME local cache and SideCar communication

If the local enrollment or user context is broken, loading or downloading content may fail.

---

# How it works

## Win32 app flow

The app list comes from the local Company Portal catalog.

The download flow:

1. Resolves the required Intune context
2. Acquires a local SideCar token through WAM
3. Retrieves ContentInfo and committedContentVersion
4. Downloads encrypted package content
5. Decrypts the IntuneWin package locally
6. Extracts the package into the selected output folder

## Remediation flow

The remediation flow uses the IME HealthScripts GetScript workload.

The tool:

1. Acquires the local SideCar WAM token
2. Uses the local Intune MDM certificate
3. Calls the HealthScripts workload through the AgentCommon communication path
4. Retrieves remediation policies directly inside the GetScript response payload
5. Decodes detect.ps1 and remediate.ps1 from the returned base64 payloads
6. Exports the raw policy JSON and signature metadata

Unlike Win32 apps, remediation scripts are not downloaded through GetContentInfo or UploadLocation URLs.

The remediation scripts are returned directly inside the GetScript response payload.

---

# Output folder

By default, downloaded content is stored under:

```text
C:\Temp\IntuneWinDownloader
```

## Win32 apps

Each app gets its own folder.

Typical output:

```text
Extracted
Metadata
Downloaded package files
Decoded package files
Logs
```

## Remediations

The remediation export contains:

```text
policy.raw.json
manifest.json
detect.ps1
remediate.ps1
content_signature.p7b
content_signature_certificates.json
```

Sensitive values such as tokens, content URLs, encryption metadata, or tenant specific information should not be published publicly.

---

# Install testing

After an app is downloaded and extracted, the Install test column shows that the app is ready for local testing.

The install test window:

* Shows the command that will be executed
* Allows editing the command before execution
* Can run silently as SYSTEM
* Can optionally remove silent switches for visible installer testing

The install test captures:

```text
Exit code
stdout
stderr
MSI log path when available
Wrapper command path
```

An exit code of 0 only means the installer process returned success.

It does not always mean the application is correctly installed.

Always validate the final installation result.

---

# Multi app download

Multiple apps can be selected and downloaded in parallel.

The tool limits worker count to avoid overloading the local SideCar and IME communication flow.

Downloaded apps are automatically marked as ready for install testing.

---

# Security notes

This tool works with local Intune related state, package metadata, remediation payloads, and local authentication flows.

Do not publish exported metadata or remediation payloads without reviewing them first.

The exported content can contain:

* Environment details
* Tenant specific identifiers
* Internal package metadata
* Script logic
* Detection logic
* Local paths
* Signing metadata

Do not run install tests on production devices unless you fully understand the installer behavior.

Do not remove silent switches unless installer UI is expected.

Do not redistribute downloaded software packages unless you have the rights to do so.

---

# Privacy notes

The tool runs locally on the device.

It uses:

* Local WAM authentication
* Local Intune enrollment state
* Local IME and Company Portal related communication flows
* Local device and user context

The tool does not upload package content or remediation data to external services.

---

# Known limitations

1. Store style applications are not the focus of this tool
2. Detection rules are not fully emulated
3. Requirement rules are not fully emulated
4. Dependencies and supersedence are not fully emulated
5. Intune reporting is not updated by local install tests
6. Local install tests do not create real Intune install records
7. Some token failures can happen when the local user state is broken
8. Some vendor wrappers may not behave exactly like the IME execution flow
9. Some metadata depends on what Company Portal or the service exposes
10. Remediation execution state reporting is not emulated
11. Some remediation payloads may eventually use encrypted policy bodies in future service versions

---

# Recommended troubleshooting flow

## Win32 apps

1. Start the app as administrator
2. Let the startup process load the app list
3. Select one or more apps
4. Download the selected apps
5. Open the extracted folder
6. Review the metadata
7. Run an install test
8. Review logs and exit codes

## Remediations

1. Open the Remediations tab
2. Download assigned remediations
3. Double click a remediation
4. Review detect.ps1 and remediate.ps1
5. Compare remediation versions if needed
6. Review raw policy JSON and signature metadata

---

# Support

There is no official support.

This project is provided as is.

Issues, pull requests, and community feedback are welcome through GitHub, but there is no guarantee of fixes, response times, or continued development.

Do not contact Patch My PC support for this tool.

---

# Version history

```text
0.1.0   Initial GUI version with Company Portal catalog discovery, SideCar GetContentInfo download, decrypt, and extract
0.2.0   WAM became the default SideCar token path. TBRES moved behind an optional legacy fallback
0.2.1   Optional TBRES fallback no longer restarts IME during token lookup
0.3.0   Improved internal functions and removed lingering TBRES logic
0.3.1   Extracted folder opens automatically after successful extraction
0.4.7   Added local install testing with user or SYSTEM execution
0.6.36  Migrated frontend to WinUI3 and backend to C#
0.6.39  Added committedContentVersion retrieval and improved dark/light mode
0.6.54  Added export function for logs and improved install/uninstall command parsing
0.6.62  Added version display to the application headers
0.6.84  Fixed select all/select app install issues and install IME policy command handling
0.6.119 Added Remediations tab using the IME HealthScripts GetScript flow
0.6.122 Added remediation script preview support
0.6.123 Added remediation pop out preview window
0.6.126 Improved remediation preview window focus handling
```

---

# Disclaimer

This project is intended for research, troubleshooting, and educational purposes.

Use responsibly and only within environments and software licensing terms you are authorized to access.
