# PSRecon
A Windows OS reconnaissance tool to perform common enumeration and security checks.

## Setup
Admin privileges aren't needed for any functions.

`PS C:\Windows\Temp> Import-Module .\PSRecon.ps1`

## Usage

### Run all host checks
`Get-HostChecks`

### Switches

#### Defense
`Get-HostChecks -Defense`
* Highlight security issues discovered by various checks.
* Useful for blue teams, security engineers, general defenders

#### DefenseOnly
`Get-HostChecks -DefenseOnly`
* Execute only checks that discover potential security issues.

#### SkipLocalAdmins
`Get-HostChecks -SkipLocalAdmins`
* Skips the local admin check

This could be necessary in larger environments with thousands of domain-based groups. The check calls the Win32_GroupUser class, which will query all domain groups as well as local ones.

## ToDo
Future additions will include:
- [ ] Add comment-based help for all functions
- [ ] Anti-virus status (real-time protection, exceptions list, date of definitions, etc.)
- [ ] EDR products (CarbonBlack, Bit9, etc.)
- [ ] GPPPassword on domain controller(s)
- [ ] SMB signing status (none, enabled, required)
- [ ] Built-in port scanner (stripped down version of Nmap)
- [ ] Proxy settings
- [ ] A filtered list of listening or established ports
