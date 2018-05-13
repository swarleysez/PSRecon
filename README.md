# PSRecon
A Windows OS reconnaissance tool to perform common enumeration and security checks.

Supported by @swarleysez

## Setup
Admin privileges aren't needed for any functions.

`PS C:\Windows\Temp> Import-Module .\PSRecon.ps1`

## Usage

### Run All Host Checks
`Get-HostChecks [-Defense] [-DefenseOnly] [-SkipLocalAdmins]`

### Individual Checks
* `Get-HostSummary` - summary of general user/host information
* `Get-HostIPAddress` - IPv4 address of all adaptors
* `Get-LocalUsers`
* `Get-LocalAdmins`
* `Get-NetVersions` - Discover installed .NET versions
* `Get-PowerShellVersions`
* `Get-PSExecutionPolicy` - PowerShell execution policy for all scopes
* `Get-PSLogging` - check PowerShell logging status (scriptblock, transcription, module)
* `Get-SMBv1` - SMBv1 enabled or disabled
* `Get-LAPS` - check for existence of Admpwd.dll file
* `Get-AntiVirus` - Currently only checks for AV products installed
* `Get-MappedDrives`
* `Get-NetShares`
* `Get-UnattendedInstallFile` - checks for file existence in several locations
* `Get-CachedGPPPassword` - checks for cached Group Policy prefernces 'cpassword'. Also includes scheduledtasksv2 type.

### Switches

#### -Defense
`Get-HostChecks -Defense`
* Highlight security issues discovered by various checks.
* Useful for blue teams, security engineers, general defenders

#### -DefenseOnly
`Get-HostChecks -DefenseOnly`
* Execute only checks that discover potential security issues.

#### -SkipLocalAdmins
`Get-HostChecks -SkipLocalAdmins`
* Skips the local admin check

This could be necessary in larger environments with thousands of domain-based groups. The check calls the Win32_GroupUser class, which will query all domain groups as well as local ones.

## ToDo
Future additions will include:
- [ ] Add comment-based help for all functions
- [ ] Domain-based checks
- [ ] Remote host execution
- [ ] Anti-virus status (real-time protection, exceptions list, date of definitions, etc.)
- [ ] EDR products (CarbonBlack, Bit9, etc.)
- [ ] GPPPassword on domain controller(s)
- [ ] SMB signing status (none, enabled, required)
- [ ] Built-in port scanner (stripped down version of Nmap)
- [ ] Proxy settings
- [ ] A filtered list of listening or established ports

## Credits
[https://github.com/PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
<br>[https://github.com/dafthack/HostRecon](https://github.com/dafthack/HostRecon)
