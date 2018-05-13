function Get-HostSummary
{
    [CmdletBinding()]
    Param()

    Write-Host ''
    Write-Host '[*]  Host Summary' -ForegroundColor Cyan

    $HostSummary =
    @{
        'Current Username' = $env:USERNAME
        'Domain' = $env:USERDNSDOMAIN
        'Hostname' = $env:COMPUTERNAME
        'LogonServer' = $env:LOGONSERVER
        'Current User Path' = $env:SystemDrive + $env:HOMEPATH
        'Public User Path' = $env:PUBLIC
    }

    # $script:OSVersion allows the variable to be called by other functions in the script
    $script:OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
        $HostSummary += @{'OS Version' = $OSVersion}

    # Sort the $HostSummary hashtable alphabetically by key. '[ordered]' can't be used, as it is a PSv3+ attribute.
    $HostSummary.GetEnumerator() | Sort-Object -Property key | Format-Table -HideTableHeaders
}


function Get-HostIPAddress
{
    Write-Host "[*] IP Address Information`n" -ForegroundColor Cyan

    $IPAddrsFull = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True'  
    foreach ($IPAddrFull in $IPAddrsFull)
    {
        $IPAddrs = $IPAddrFull.IPAddress
        foreach ($IPAddr in $IPAddrs)
        {
            if (!($IPAddr -like "fe*"))
            {
                Write-Output "$IPAddr`t`t$($IPAddrFull.Description)"
            }
        }
    }
}


function Get-LocalUsers
{
    [CmdletBinding()]
    Param()

    Write-Host "`n"
    Write-Host '[*] Active Local Users' -ForegroundColor Cyan
       
    # Win32_UserAccount will query all domain users as well, so filter for LocalAccounts first. `
    # Do not filter after the fact.  Exmaple: 'Where-Object {$_.LocalAccount -eq $true}'    
    $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"
    $ActiveLocalUsers = $LocalUsers | Where-Object {$_.Disabled -eq $false}
    $ActiveLocalUsers | Format-Table -Property Name -HideTableHeaders
}


function Get-LocalAdmins
{
    [CmdletBinding()]
    Param()

    Write-Host "[*] Local Admins`n" -ForegroundColor Cyan
    
    # Querying the Win32_GroupUser Class on large domains is causing a large latency in script completion
    $AdminGroup = Get-WmiObject -Class Win32_GroupUser | Where-Object {$_.GroupComponent -match "administrators" `
                                -and ($_.GroupComponent -match "Domain=`"$env:COMPUTERNAME`"")}
    # $AdminGroup = Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True'"

    foreach ($AdminUser in $AdminGroup)
    {
        $AdminSplit = $AdminUser.partcomponent | Out-String
        $AdminUserSplit = ((($AdminSplit.Split('=')[-1]).Substring(1)).Trim()).TrimEnd('"')
        $AdminDomainSplit = $AdminSplit.Split('"')[1]
        Write-Output "$AdminDomainSplit\$AdminUserSplit"
    }
}


function Get-NETVersions
{
    [CmdletBinding()]
    Param
    (
        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] .NET Versions Installed`n" -ForegroundColor Cyan

    # The '-Directory' parameter for Get-ChildItem is a PSv3+ option. '-Path' is used here instead.
    $DotNetVers = Get-ChildItem -Path C:\Windows\Microsoft.NET\Framework -Name "v*"

    foreach ($DotNetVer in $DotNetVers)
    {
        $DotNetVerFile = Get-ChildItem -Path C:\Windows\Microsoft.Net\Framework\$DotNetVer\System.dll -ErrorAction SilentlyContinue
    
        if ($DotNetVerFile)
        {
            if ($DotNetVer -eq 'v2.0.50727' -and $Defense)
            {
                    Write-Warning "$DotNetVer"
            }

            else
            {
                Write-Output "$DotNetVer"
            }
        }
    }
}    


function Get-PowerShellVersions
{
    [CmdletBinding()]
    Param
    (
        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] PowerShell Versions Installed`n" -ForegroundColor Cyan

    $PSRegEngVers = (1..5)

    foreach ($PSRegEngVer in $PSRegEngVers)
    {      
        $PSRegEng = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell\$PSRegEngVer\PowerShellEngine -ErrorAction SilentlyContinue
        if ($PSRegEng)
        {

            if ($($PSRegEng.PowerShellVersion -eq '2.0'))
            {
                if ($Defense)
                {
                    Write-Warning "Ver: $($PSRegEng.PowerShellVersion)"
                }

                else
                {
                    Write-Output "Ver: $($PSRegEng.PowerShellVersion)"
                }
            }

            else
            {
                if ($Defense)
                {
                    Write-Output "Ver: $($PSRegEng.PowerShellVersion)"
                }

                else
                {
                    Write-Warning "Ver: $($PSRegEng.PowerShellVersion)"
                }
            }
        }
    }
}


function Get-PSExecPolicy
{
    [CmdletBinding()]
    Param()

    Write-Host "`n"
    Write-Host "[*] PowerShell Execution Policy`n" -ForegroundColor Cyan

    $PSExecPolicy = Get-ExecutionPolicy -List
    # PSv5 has a default timeout of 300ms for built-in modules that use 'Format-Table `
    # by default. Explicitly using 'Format-Table' will ignore that default timeout.
    Write-Output $PSExecPolicy | Format-Table -AutoSize
    Write-Output "[!] Note: The execution policy was never meant to be used as a mitigation against malicious execution."
}


function Get-PSLogging
{
    [CmdletBinding()]
    Param
    (
        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] PowerShell Logging Status`n" -ForegroundColor Cyan

    $PSSBL = Get-ItemProperty -Path HKLM:SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue
    if ($PSSBL)
    {
    
        if ($PSSBL.EnableScriptBlockLogging -eq 1)
        {
            if ($Defense)
            {
                Write-Output 'Scriptblock logging: Enabled'
            }

            else
            {
                Write-Warning 'Scriptblock logging: Enabled'
            }
        }

        elseif ($PSSBL.EnableScriptBlackLogging -eq 0)
        {
            if ($Defense)
            {
                Write-Warning 'Scriptblock logging: Disabled'
            }

            else
            {
                Write-Output 'Scriptblock logging: Disabled'
            }
        }
        
    }

    else
    {
        if ($Defense)
        {
            Write-Warning 'Scriptblock Logging: Registry key does not exist'
        }

        else
        {
            Write-Output 'Scriptblock Logging: Registry key does not exist'
        }
    }

    $PSTrans = Get-ItemProperty -Path HKLM:SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription -Name 'EnableTranscripting' -ErrorAction SilentlyContinue
    if ($PSTrans)
    {
        if ($PSTrans.EnableTranscripting -eq 1)
        {
            if ($Defense)
            {
                Write-Output 'Transcription logging: Enabled'
            }

            else
            {
                Write-Warning 'Transcription logging: Enabled'
            }
        }

        elseif ($PSTrans.EnableTranscripting -eq 0)
        {
            if ($Defense)
            {
                Write-Warning 'Transcription logging: Disabled'
            }

            else
            {
                Write-Output 'Transcription logging: Disabled'
            }
        }
    }

    else
    {
        if ($Defense)
        {
            Write-Warning 'Transcription: Registry key does not exist'
        }

        else
        {
            Write-Output 'Transcription: Registry key does not exist'
        }
    }

    $PSModLog = Get-ItemProperty -Path HKLM:SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
    if ($PSModLog)
    {
        if ($PSModLog.EnableModuleLogging -eq 1)
        {
            if ($Defense)
            {
                Write-Output 'Module logging: Enabled'
            }

            else
            {
                Write-Warning 'Module logging: Enabled'
            }
        }

        elseif ($PSModLog.EnableModuleLogging -eq 0)
        {
            if ($Defense)
            {
                Write-Warning 'Module logging: Disabled'
            }

            else
            {
                Write-Output 'Module logging: Disabled'
            }
        }
    }

    else
    {
        if ($Defense)
        {
            Write-Warning 'Module Logging: Registry key does not exist'
        }

        else
        {
            Write-Output 'Module Logging: Registry key does not exist'
        }
    }
}


function Get-SMBv1
{
    [CmdletBinding()]    
    Param
    (
        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] Checking for SMBv1`n" -ForegroundColor Cyan

    # SMBv1 is enabled by default, so if registry value is missing or = 1, SMBv1 is enabled.
    # Only if the registry key is present and = 0 is SMBv1 disabled.  
    # Next line returns $null if registry key is missing, else returns value of "SMB1" (DWORD 0 or 1)
    $SMBv1Reg = (Get-ItemProperty -Path `
                    "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                    SMB1 -ErrorAction SilentlyContinue).SMB1
    
    if ($SMBv1Reg -eq $null)
    {
        if ($Defense)
        {
            Write-Warning 'The registry value for SMB1 is missing (default = 1), which means it is enabled.'
        }

        else
        {
            Write-Output 'The registry value for SMB1 is missing (default = 1), which means it is enabled.'
        }
    }
    
    elseif ($SMBv1Reg -ne 0)
    { 
        if ($Defense)
        {
            Write-Warning 'SMBv1 is Enabled'
        }

        else
        {
            Write-Output 'SMBv1 is Enabled'
        }
    }
        
    else
    {
        Write-Output 'SMBv1 is NOT enabled'
    }
}


function Get-SMBSigning
{
    [CmdletBinding()]
    Param
    (
        $localhost = 'localhost',

        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] Checking for SMB Signing`n" -ForegroundColor Cyan
    
    $WinClientVers = @(".10.",".7.",".XP.",".Vista.")
    $WinServerVers = @(".2000.",".2003.",".2008.",".2012.",".2016.")

    if ($WinClientVers | Where-Object {$OSVersion -match $_})
    {
        $SMBSignWKS = (Get-ItemProperty -Path `
        "HKLM:\SYSTEM\CurrentControlSet\Services\Rdr\Parameters" `
        SMB1 -ErrorAction SilentlyContinue).SMB1

        if ($SMBv1Reg -eq $null)
        {
        if ($Defense)
        {
        Write-Warning 'The registry value for SMB1 is missing (default = 1), which means it is enabled.'
        }

        else
        {
        Write-Output 'The registry value for SMB1 is missing (default = 1), which means it is enabled.'
        }
        }

        elseif ($SMBv1Reg -ne 0)
        { 
        if ($Defense)
        {
        Write-Warning 'SMBv1 is Enabled'
        }

        else
        {
        Write-Output 'SMBv1 is Enabled'
        }
        }

        else
        {
        Write-Output 'SMBv1 is NOT enabled'
        }
    }

    elseif ($WinServerVers | Where-Object {$OSVersion -match $_})
    {
        
    }

    else
    {
        if ($Defense)
        {
            Write-Warning 'SMB Signing...'
        }

        else
        {
            Write-Ouput 'SMB Signing...'
        }
    }
}


function Get-LAPS
{
    [CmdletBinding()]
    Param
    (
        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] LAPS Installation Status`n" -ForegroundColor Cyan

    try
    {
        $LAPS = Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll' -ErrorAction Stop
        if ($LAPS)
        {
            if ($Defense)
            {
                Write-Output "LAPS DLL discovered. LAPS might be enabled."
            }

            else
            {
                Write-Warning "LAPS DLL discovered. LAPS might be enabled."
            }
        }
    }
    
    <# It does not seem like this .NET Namespace class can be used in PSv2. Need to Research this.
    
    catch [System.Management.Automation.ItemNotFoundException]
    {
        Write-Output 'LAPS is not installed'
    }
    #>

    catch
    {
        if ($Defense)
        {
            Write-Warning "LAPS is not installed."
        }

        else
        {
            Write-Output "LAPS is not installed."
        }
    }
}


function Get-AntiVirus
{
    [CmdletBinding()]
    Param
    (
        $localhost = 'localhost',

        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] AntiVirus Products`n" -ForegroundColor Cyan
    
    # This needs some work. Need this to check for AV, and if none found, then report "No AV products found."
    # If the $OSVersion is a Windows Client OS, then query the SecurityCenter<2> Namespace
    $WinClientVers = @(".10.",".7.",".XP.",".Vista.")
    $WinServerVers = @(".2000.",".2003.",".2008.",".2012.",".2016.")

    if ($WinClientVers | Where-Object {$OSVersion -match $_})
    {
        $NSDirs = ('SecurityCenter','SecurityCenter2')
            foreach ($NSDir in $NSDirs)
            {
                try
                {
                    $AVProd = Get-WmiObject -Namespace root\$NSDir -Class AntiVirusProduct -ErrorAction Stop
                    if ($AVProd)
                    {
                        if ($Defense)
                        {
                            Write-Output "$($AVProd.displayName) is installed."
                        }

                        else
                        {
                            Write-Warning "$($AVProd.displayName) is installed."
                        }
                    }
                }

                catch
                {
                    if ($Defense)
                    {
                        Write-Warning 'No AV products found.'
                    }

                    else
                    {
                        Write-Output 'No AV products found.'
                    }
                }
            }
    }

    elseif ($WinServerVers | Where-Object {$OSVersion -match $_})
    {
        # Code for registry hive query, searching for Windows Server AV, is from
        # https://stackoverflow.com/questions/33649043/powershell-how-to-get-antivirus-product-details"

        # $computerList = "localhost"   <---No current need to search through a list of hosts
        $results = @()
        # foreach($computerName in $computerList)
        #{   <---No current need to search through a list of hosts

            $Reghive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $localhost)
            $regPathList = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                            "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

            foreach($regPath in $regPathList)
            {
                if($key = $Reghive.OpenSubKey($regPath))
                {
                    if($subkeyNames = $key.GetSubKeyNames())
                    {
                        foreach($subkeyName in $subkeyNames)
                        {
                            $productKey = $key.OpenSubKey($subkeyName)
                            $productName = $productKey.GetValue("DisplayName")
                            $productVersion = $productKey.GetValue("DisplayVersion")
                            $productComments = $productKey.GetValue("Comments")

                            # The match in the array is not case-sensitive (i.e. ".Malware." == ".malware.")
                            $filters = @(".Endpoint Protection.",".AntiVirus.",".Malware.",".Defender.")
                            foreach ($filter in $filters)
                            {
                                if(($productName -match $filter) -or ($productComments -match $filter))
                                {
                                    $resultObj = [PSCustomObject]
                                    @{
                                        Host = $computerName
                                        Product = $productName
                                        Version = $productVersion
                                        Comments = $productComments
                                    }
                                    $results += $resultObj

                                    $hostexec = $env:COMPUTERNAME
                                    Write-Output "The is a property of $($hostexec.Property)"
                                }
                            }
                        }
                    }
                    $key.Close()
                }
            }
            $results | Format-Table -AutoSize
        #}
    }

    else
    {
        if ($Defense)
        {
            Write-Warning 'No AV products found.'
        }

        else
        {
            Write-Output 'No AV products found.'
        }
    }
}


function Get-MappedDrives
{
    [CmdletBinding()]
    Param()

    Write-Host "`n"
    Write-Host "[*] Mapped Drives`n" -ForegroundColor Cyan
    
    $MappedDrives = Get-WmiObject -Class Win32_MappedLogicalDisk
    if ($MappedDrives)
    {
        Write-Output $MappedDrives | Format-Table -Property Caption,ProviderName -AutoSize
    }
    else
    {
        Write-Output "No Mapped Drives Found"
    }
}


function Get-NetShares
{
    [CmdletBinding()]
    Param()

    Write-Host "`n"
    Write-Host "[*] Net Shares`n" -ForegroundColor Cyan
    
    $NetShares = Get-WmiObject -Class Win32_Share
        
    foreach ($NetShare in $NetShares)
    {
        $NetPath = $NetShare.Path

        try
        {
            $AccessRights = Get-Acl $NetPath | Select-Object -Expand Access
            $NetPath
            $AccessRights | Format-Table -Property FileSystemRights, AccessControlType, IdentityReference
        }
        catch{}
    }
}


function Get-UnattendedInstallFile
{
    [CmdletBinding()]
    Param
    (
        [switch]
        $Defense
    )

    <#
        .SYNOPSIS
            Checks several locations for remaining unattended installation files,
            which may have deployment credentials.

            Author: @harmj0y
        .EXAMPLE
            PS C:\> Get-UnattendedInstallFile
            Finds any remaining unattended installation files.
        .LINK
            http://www.fuzzysecurity.com/tutorials/16.html
    #>

    Write-Host "`n"
    Write-Host "[*] Unattended Install File Search`n" -ForegroundColor Cyan

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations = @(   "c:\sysprep\sysprep.xml",
                            "c:\sysprep\sysprep.inf",
                            "c:\sysprep.inf",
                            "c:\unattend.xml",
                            "c:\unattended.xml",
                            "C:\Autounattend.xml",
                            (Join-Path $Env:WinDir "\Panther\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\Panther\unattend.xml")
                        )

    # test the existence of each path and return anything found
    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'UnattendPath' $_
    }

    if ($Out)
    {
        if ($Defense)
        {
            Write-Warning $Out
        }

        else
        {
            Write-Output $Out    
        }
    }

    else
    {
        Write-Output "Unattended install file not found."
    }

    $ErrorActionPreference = $OrigError
}


function Get-CachedGPPPassword
{
    <#
    .SYNOPSIS

    Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences and
    left in cached files on the host.
    Author: Chris Campbell (@obscuresec)  
    License: BSD 3-Clause  
    Required Dependencies: None  

    .DESCRIPTION

    Get-CachedGPPPassword searches the local machine for cached for groups.xml, scheduledtasks.xml, services.xml and
    datasources.xml files and returns plaintext passwords.

    .EXAMPLE

    Get-CachedGPPPassword
    NewName   : [BLANK]
    Changed   : {2013-04-25 18:36:07}
    Passwords : {Super!!!Password}
    UserNames : {SuperSecretBackdoor}
    File      : C:\ProgramData\Microsoft\Group Policy\History\{32C4C89F-7
                C3A-4227-A61D-8EF72B5B9E42}\Machine\Preferences\Groups\Gr
                oups.xml

    .LINK

    http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
    https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
    https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
    http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
    http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
    #>
    
    [CmdletBinding()]
    Param()

    Write-Host "`n"
    Write-Host '[*] Checking for Cached GPP Passwords' -ForegroundColor Cyan

    # Some XML issues between versions
    Set-StrictMode -Version 2

    # make sure the appropriate assemblies are loaded
    Add-Type -Assembly System.Security
    Add-Type -Assembly System.Core

    # helper that decodes and decrypts password for cPasswords in GPP
    function script:Get-DecryptedCpassword
    {
            
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
        [CmdletBinding()]
        Param
        (
            [string]
            $Cpassword
        )
    
        try
        {
            # Append appropriate padding based on string length
            $Mod = ($Cpassword.length % 4)
    
            switch ($Mod)
            {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }
    
            $Base64Decoded = [Convert]::FromBase64String($Cpassword)
    
            # Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                    0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
    
            # Set IV to all nulls to prevent dynamic generation of IV value
            $AesIV = New-Object Byte[]($AesObject.IV.Length)
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor()
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
    
            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        }
        
        catch
        {
            Write-Error $Error[0]
        }
    }

    # helper that parses fields from the found xml preference files
    function Get-GPPInnerField
    {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
        [CmdletBinding()]
        Param(
            $File
        )

        try
        {
            $Filename = Split-Path $File -Leaf
            [XML] $Xml = Get-Content ($File)

            $Cpassword = @()
            $UserName = @()
            $NewName = @()
            $Changed = @()
            $Password = @()

            # check for password field
            if ($Xml.innerxml -like "*cpassword*")
            {

                Write-Verbose "Potential password in $File"

                switch ($Filename)
                {
                    'Groups.xml'
                    {
                        $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Services.xml'
                    {
                        $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Scheduledtasks.xml'
                    {
                        $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/TaskV2/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/ScheduledTasks/TaskV2/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/ScheduledTasks/TaskV2/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'DataSources.xml'
                    {
                        $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Printers.xml'
                    {
                        $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Drives.xml'
                    {
                        $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                }
            }

            ForEach ($Pass in $Cpassword)
            {
                Write-Verbose "Decrypting $Pass"
                $DecryptedPassword = script:Get-DecryptedCpassword $Pass
                Write-Verbose "Decrypted a password of $DecryptedPassword"
                #append any new passwords to array
                $Password += , $DecryptedPassword
            }

            # put [BLANK] in variables
            if (-not $Password) {$Password = '[BLANK]'}
            if (-not $UserName) {$UserName = '[BLANK]'}
            if (-not $Changed)  {$Changed = '[BLANK]'}
            if (-not $NewName)  {$NewName = '[BLANK]'}

            # Create custom object to output results
            $ObjectProperties = @{'Passwords' = $Password;
                                    'UserNames' = $UserName;
                                    'Changed' = $Changed;
                                    'NewName' = $NewName;
                                    'File' = $File}

            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Write-Verbose "The password is between {} and may be more than one value."
            if ($ResultsObject) { Return $ResultsObject }
        }

        catch {Write-Error $Error[0]}
    }

    try
    {
        $AllUsers = $Env:ALLUSERSPROFILE

        if ($AllUsers -notmatch 'ProgramData')
        {
            $AllUsers = "$AllUsers\Application Data"
        }

        # discover any locally cached GPP .xml files
        $XMlFiles = Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue

        if ( -not $XMlFiles )
        {
            Write-Verbose 'No preference files found.'
        }

        else
        {
            Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."

            ForEach ($File in $XMLFiles)
            {
                Get-GppInnerField $File.Fullname
            }
        }
    }

    catch
    {
        Write-Error $Error[0]
    }
}    


function Get-HostChecks
{
    [CmdletBinding()]
    Param
    (
        [switch]
        $Defense,

        [switch]
        $DefenseOnly,

        [switch]
        $SkipLocalAdmins
    )

    if ($DefenseOnly)
    {
        Get-HostSummary
        Get-HostIPAddress
        Get-NETVersions -Defense
        Get-PowerShellVersions -Defense
        Get-PSLogging -Defense
        Get-SMBv1 -Defense
        Get-LAPS -Defense
        Get-AntiVirus -Defense
        Get-UnattendedInstallFile -Defense
        Get-CachedGPPPassword
    }

    else
    {
        Get-HostSummary
        Get-HostIPAddress
        Get-LocalUsers
        
        if (-Not ($SkipLocalAdmins))
        {
            Get-LocalAdmins
        }

        Get-PSExecPolicy

        if ($Defense)
        {
            Get-NETVersions -Defense
            Get-PowerShellVersions -Defense
            Get-PSLogging -Defense
            Get-SMBv1 -Defense
            Get-LAPS -Defense
            Get-AntiVirus -Defense
            Get-UnattendedInstallFile -Defense
        }

        else
        {
            Get-NETVersions
            Get-PowerShellVersions
            Get-PSLogging
            Get-SMBv1
            Get-LAPS
            Get-AntiVirus
            Get-UnattendedInstallFile
        }

        Get-MappedDrives
        Get-NetShares
        Get-CachedGPPPassword
    }
}


function Get-NetworkChecks
{
    [CmdletBinding()]
    Param
    (
        #[ValidateNotNullOrEmpty] <-- Throwing errors. Version errors originate from?
        [string]
        $Domain
    )

    try
    {
        $ADSites = nltest /dsaddresstosite:$Domain
        Write-Output $ADSites
    }

    catch
    {
        Write-Warning 'That domain could not be resolved.'
    }
}