# TechXplored Phantom Boot Entry Inspector

Evidence-first Windows BCD diagnostics for phantom, stale, duplicate, and broken boot-menu entries.

**Version:** 0.1.0-alpha  
**Safety model:** read-only. This version never modifies the BCD store.

## What it inspects

The inspector runs:

```text
bcdedit /enum all /v
```

It parses the resulting BCD objects and correlates the Windows Boot Manager `displayorder` with the referenced loaders.

Current findings include:

- visible boot-menu identifiers whose referenced BCD object is missing;
- visible entries referencing `$Windows.~BT` / Windows Setup temporary files;
- Windows Setup, rollback, installation, or temporary-looking menu entries;
- drive-letter based `device` or `osdevice` references to inaccessible volumes;
- missing `systemroot` directories on directly addressable volumes;
- missing `winload.exe` / `winload.efi` targets on directly addressable volumes;
- multiple visible entries that appear to target the same Windows installation;
- Windows Setup BCD remnants outside the visible boot menu.

## Important limitation

BCD can legitimately reference hidden EFI, recovery, RAM-disk, VHD, and device paths that do not have drive letters. Version 0.1 deliberately does **not** call those broken merely because they cannot be mapped to a normal drive letter. False negatives are preferable to destructive guesses.

## Build

From the repository root on Windows with the .NET 10 SDK installed:

```powershell
dotnet build -c Release
```

## Run

Open an elevated Windows Terminal / PowerShell prompt and run:

```powershell
dotnet run -c Release
```

For machine-readable output:

```powershell
dotnet run -c Release -- --json
```

To include remediation **previews**:

```powershell
dotnet run -c Release -- --preview-remediation
```

A preview can look like:

```text
bcdedit /displayorder {GUID} /remove
```

The command is printed for review only. The program does not execute it.

## Exit codes

- `0` — scan completed with no HIGH or CRITICAL findings;
- `1` — the inspector itself failed;
- `2` — scan completed and at least one HIGH or CRITICAL finding was detected.

## Example

```text
TECHXPLORED PHANTOM BOOT ENTRY INSPECTOR
=======================================
BCD objects examined : 14
Boot-menu entries    : 2
Running elevated     : Yes

[HIGH] Boot entry points into temporary Windows Setup files
  Entry:    {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
  Reason:   This visible boot entry references $Windows.~BT or another Windows Setup temporary path.
  Evidence: device = partition=C:\$Windows.~BT\...
  Preview:  bcdedit /displayorder {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} /remove

No BCD entries were changed.
```

## Direction for v0.2

Before adding any automatic repair operation, the inspector should gain:

1. EFI and recovery partition mapping;
2. BCD reference-graph analysis (`resumeobject`, recovery sequences, ramdisk options, etc.);
3. confidence scoring for each finding;
4. differentiation between stale-but-harmless BCD objects and entries that can actually appear at startup;
5. exportable diagnostic bundles for support / TechXplored Services Workbench integration;
6. tests using captured, sanitized BCD samples representing known-good and known-bad configurations.

Automatic deletion is intentionally not part of v0.1.
