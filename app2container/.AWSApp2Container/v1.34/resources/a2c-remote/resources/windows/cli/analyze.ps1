# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string] $schemaVersion,

    [Parameter(Mandatory = $true)]
    [string] $appName,

    [Parameter(Mandatory = $true)]
    [string] $appId,

    [Parameter(Mandatory = $true)]
    [string] $appType, # Either iis or service

    [Parameter(Mandatory = $true)]
    [string] $workspacePath,

    [Parameter(Mandatory = $false)]
    [string] $disableTermNiceties
)

Import-module "$PSScriptRoot\utils\logUtil.ps1" -Force

Import-module "$PSScriptRoot\utils\jsonUtil.ps1" -Force

Import-module "$PSScriptRoot\utils\errorUtil.ps1" -Force

Import-module "$PSScriptRoot\utils\pathUtil.ps1" -Force

enum AppType {
    Unknown
    IIS
    Service
}

[AppType] $script:appTypeEnum = [AppType]::Unknown

$script:editableFilePath = ""

$script:reportFilePath = ""

$script:backupLocalPath = ""

$script:backupFileName = ""

$script:reportFile = ""

$script:currentPath = ""

$script:commandType = "Analyze"

$script:siteUsesWindowsAuth = $false

$script:wdInstallerPath = "$PSScriptRoot\..\tools\WebDeploy_amd64_en-US.msi"

$script:defaultImageFeatures = @("FileAndStorage-Services"
                                    ,"Storage-Services"
                                    ,"Web-Server"
                                    ,"Web-WebServer"
                                    ,"Web-Common-Http"
                                    ,"Web-Default-Doc"
                                    ,"Web-Dir-Browsing"
                                    ,"Web-Http-Errors"
                                    ,"Web-Static-Content"
                                    ,"Web-Health"
                                    ,"Web-Http-Logging"
                                    ,"Web-Performance"
                                    ,"Web-Stat-Compression"
                                    ,"Web-Security"
                                    ,"Web-Filtering"
                                    ,"Web-App-Dev"
                                    ,"Web-Net-Ext45"
                                    ,"Web-Asp-Net45"
                                    ,"Web-ISAPI-Ext"
                                    ,"Web-ISAPI-Filter"
                                    ,"NET-Framework-45-Features"
                                    ,"NET-Framework-45-Core"
                                    ,"NET-Framework-45-ASPNET"
                                    ,"NET-WCF-Services45"
                                    ,"NET-WCF-TCP-PortSharing45"
                                    ,"System-DataArchiver"
                                    ,"PowerShellRoot"
                                    ,"PowerShell"
                                    ,"WoW64-Support")

function Check-Prerequisites {
    New-Message $InfoMsg "Checking prerequisites..."
    $psVersion = $PSVersionTable.PSVersion.Major
    if ($psVersion -lt 5) {
        # customers facing error will be errors.PSVersionCheckError message, this message is for logs
        New-Message $ErrorMsg "PSVersionCheckError" "Current PowerShell Version: $psVersion"
        Exit-Application
    }
    if ([Environment]::Is64BitProcess -ne $True) {
        New-Message $ErrorMsg "PSIsNot64BitProcess"
        Exit-Application
    }

    if ($appType -eq "IIS") {
        $script:appTypeEnum = [AppType]::IIS
        if ((Get-WindowsFeature Web-Server).Installed -ne $True) {
            New-Message $ErrorMsg "IISInstNotFound"
            Exit-Application
        }

        try {
            Import-Module WebAdministration -ErrorAction Stop
        } catch {
            New-Message $ErrorMsg "ImportWebAdminErr"
            Exit-Application
        }
    } elseif ($appType -eq "Service") {
        $script:appTypeEnum = [AppType]::Service
    } else {
        New-Message $ErrorMsg "InvalidAppType" "$appType"
        Exit-Application
    }
}

function Prepare-Inputs {
    $workspacePath = $workspacePath | Resolve-Env
    if (-not (Test-Path $workspacePath)) {
        New-Message $ErrorMsg "ValidWorkspaceReq" "Current Path: $workspacePath"
        Exit-Application
    }
    $script:currentLocation = Get-Location

    if ($appTypeEnum -eq [AppType]::IIS) {
        $site = Get-Website | Where-Object { $_.name -eq $appName }
        if ((-Not$site)) {
            New-Message $ErrorMsg "IISSiteNotFound"
            Exit-Application
        }
    } elseif ($appTypeEnum -eq [AppType]::Service) {
        $serviceIsRunning = Get-Service $appName | Select-Object -ExpandProperty Status
        if ($serviceIsRunning -ne "Running") {
            New-Message $ErrorMsg "ServiceNotRunning"
            Exit-Application
        }
    }

    $script:editableFilePath = $workspacePath + "\" + $appId + "\EditableFiles\"
    $script:reportFilePath = $workspacePath + "\" + $appId + "\"
}

function Prepare-EditableFiles {
    New-Message $InfoMsg "Detecting editable files..."
    try {
        Create-Dir -path $script:editableFilePath -cleanDir $true
    } catch {
        New-Message $ErrorMsg "CreateEditDirFail" $_.Exception.Message
        Exit-Application
    }

    Add-Content $script:reportFile "*** The below section shows the connection strings and configuration locations detected for your application. ***" | out-null

    #Search root path
    $rootPath = $( Get-WebSite | Where-Object { $_.name -eq $appName } ).physicalPath | Resolve-Env
    $rootPath = $rootPath -replace '[\\]', '\$&'
    $rootPath = $rootPath -replace '\\\\\\\\', '\\'
    New-Message $InfoMsg "Processing website root path: '$rootPath'."
    Add-Content $script:reportFile "`n<--- Connection string file(s) for the root website in '$rootPath' --->" | out-null
    Get-PossibleDBConnStringFiles -path $rootPath
    Add-Content $script:reportFile "`n<--- Config file(s) for the root website in '$rootPath' --->" | out-null
    Get-ConfigFiles -path $rootPath

    #Search applications
    $appPaths = $( Get-WebApplication -Site $appName ).physicalPath
    foreach ($path in $appPaths) {
        $path = $path -replace '[\\]', '\$&'
        $path = $path -replace '\\\\\\\\', '\\'
        $path = $path | Resolve-Env
        if (-Not($path.Contains($rootPath))) {
            New-Message $InfoMsg "Processing application path: '$path'."
            Add-Content $script:reportFile "`n<--- Connection string file(s) for the application in '$path' --->" | out-null
            Get-PossibleDBConnStringFiles -path $path
            Add-Content $script:reportFile "`n<--- Config file(s) for the application in '$path' --->" | out-null
            Get-ConfigFiles -path $path
        }
    }
    Add-Content $script:reportFile "`n*** The file paths above have been replicated in $script:editableFilePath, These files can be updated and the changes will be included in the container build.***" | out-null
    New-Message $InfoMsg "Editable files detection completed, you can find the report at '$script:reportFile'."
    New-Message $InfoMsg "If you want to edit the files, please go to '$script:editableFilePath'. All changes will be included in the container build."
}

function Get-PossibleDBConnStringFiles([String]$path) {
    # copies over all files with content matching $connStrPatterns to $newPath and also writes all matching results to $reportFile
    $connStrPatterns = "DataSource=.*UserId=.*Password=.*",
                        "Server=.*Database=.*User Id=.*Password=.*",
                        "User ID=.*Password=.*Host=.*Port=.*Database=.*Pooling=.*Min Pool Size=.*Max Pool Size=.*Connection Lifetime=.*",
                        "Provider=.*Data Source=.*location=.*User ID=.*password=.*timeout=.*",
                        "Server=.*Database=.*Uid=.*Pwd=.*",
                        "Database=.*Protocol=.*User Id=.*Password=.*",
                        "Provider=.*User Id=.*Password=.*",
                        "Provider=.*Data Source=.*",
                        "Provider=.*OledbKey1=.*OledbKey2=.*",
                        "Data Source=.*Version=.*",
                        "Data Source=.*Persist Security Info=.*",
                        "Server=.*User ID=.*Password=.*Trusted_Connection=.*Encrypt=.*",
                        "Data Source=.*Integrated Security=.*"
    # Get-ChildItem recursively reads all files under $path and returns a list of file paths
    # Select-String then reads all the files and returns a list of MatchInfo object that match $connStrPatterns
    # https://learn.microsoft.com/en-us/dotnet/api/microsoft.powershell.commands.matchinfo?view=powershellsdk-7.2.0
    $results = Get-ChildItem -Path $path -Recurse -exclude "*.exe","*.dll" -ErrorAction Stop | Select-String -Pattern $connStrPatterns
    $lines = [System.Collections.ArrayList]@()
    $relativePathRoot = (get-item $path).parent.FullName
    Set-Location $relativePathRoot
    foreach ($result in $results) {
        $sections = $result -split ':'

        #Copy editable files
        $fileFound = $result.Path
        $folder = $(Get-Item $fileFound.ToString()).Directory.FullName
        $relativePath = Get-Item $folder | Resolve-Path -Relative
        $newPath = Join-Path -Path $script:editableFilePath -ChildPath $relativePath
        if (!(Test-Path -path $newPath)) {
            New-Item $newPath -Type Directory | out-null
        }
        Copy-Item $fileFound -Destination $newPath -Force | out-null

        #Add to report
        $location = $fileFound + ":" + $sections[2]
        $connString = ""
        for ($i = 3; $i -lt $sections.Length; $i++){
            $connString += $sections[$i]
        }
        $lines.Add($location + "  ------->  " + $connString.trim()) | out-null
    }
    foreach ($line in $lines) {
        Add-Content $reportFile $line
    }
    Set-Location $script:currentLocation
}

Function Get-ConfigFiles([String]$path) {
    $webConfigFile = $path + "\Web.config"
    if (Test-Path $webConfigFile) {
        Add-Content $script:reportFile $webConfigFile | out-null
        $parentDir = (get-item $path).Name
        $newPath = Join-Path -Path $script:editableFilePath -ChildPath $parentDir
        if (!(Test-Path -path $newPath)) {
            New-Item $newPath -Type Directory | out-null
        }
        Copy-Item $webConfigFile -Destination $newPath -Force | out-null
    }
}

function Is-Site-Using-Windows-Auth {
    try {
        $webConfig = Get-WebConfiguration system.web/authentication -Recurse -PSPath "MACHINE/WEBROOT/APPHOST/$appName"
        if (($webConfig -ne $null) -And ($webConfig.mode -like "Windows")) {
            $script:siteUsesWindowsAuth = $true
        }
        if (!$script:siteUsesWindowsAuth) {
            $appConfig = Get-WebConfiguration system.webServer/security/authentication/windowsAuthentication -Recurse -Location $appName
            if (($appConfig -ne $null) -And ($appConfig.enabled)) {
                $script:siteUsesWindowsAuth = $true
            }
        }
    } catch {
        New-Message $InfoMsg "Could not determine site authentication from WebConfig or appHostConfig"
    }
}


function Backup-ServerConfig {
    $WebDeployInstalled = Get-WmiObject Win32_Product | ? {$_.Name -like '*Microsoft Web Deploy*'}
    if ($WebDeployInstalled -eq $null) {
        New-Message $InfoMsg "Installing WebDeploy..."
        if (-not (Test-Path $script:wdInstallerPath)) {
            New-Message $InfoMsg "Could not find WebDeploy install file. Continuing ..."
            Return
        }
        Start-Process $script:wdInstallerPath '/qn' -PassThru | Wait-Process
        if ($LASTEXITCODE -and ($LASTEXITCODE -ne 0)) {
            New-Message $ErrorMsg "InstallWebDeployErr"
            Exit-Application
        }
    } else {
        New-Message $InfoMsg "WebDeploy already installed."
    }
    Add-PSSnapin WDeploySnapin3.0
    $backupResult = Backup-WDServer -ConfigOnly -ErrorAction SilentlyContinue
    $script:backupLocalPath = $backupResult.Package
    if (!$script:backupLocalPath) {
        $errMsg = $Error[0]
        New-Message $InfoMsg $errMsg
        New-Message $InfoMsg "Could not generate server backup. Continuing ..."
    } else {
        $script:backupFileName = split-Path -Path $script:backupLocalPath -Leaf
        New-Message $InfoMsg "Server backup generated: '$script:backupFileName'"
    }
}

function Generate-IISInfo {
    $script:reportFile = $script:reportFilePath + "report.txt"
    New-Item $reportFile | out-null

    $appPool = (Get-Item "IIS:\Sites\$appName" | Select-Object applicationPool).applicationPool
    $poolInfo = Get-Item "IIS:\AppPools\$appPool" | Select-Object

    $webApps = Get-WebApplication -Site "$appName"
    $appVirtualDirs = @{ }
    ForEach ($webapp in $webApps) {
        $webAppName = $webapp.Path.Trim('/')
        $vdirs = Get-WebVirtualDirectory -Site "$appName" -Application "$webAppName"
        $dirs = @()
        if ($vdirs) {
            ForEach ($vdir in $vdirs) {
                $dirObj = New-Object psobject -Property @{dirName = $vdir.Path.Trim('/'); dirPath = $vdir.PhysicalPath}
                $dirs += $dirObj
            }
        }
        $appVirtualDirs[$webAppName] = $dirs
    }
    Is-Site-Using-Windows-Auth
    [PSCustomObject]@{
        poolName = $poolInfo.Name
        poolIdentityType = $poolInfo.processmodel.IdentityType.ToString()
        sitePhysicalPath = $( Get-WebSite | Where-Object { $_.name -eq $appName } ).physicalPath | Resolve-Env
        appVirtualDirs = $appVirtualDirs
        dotNetVersion = $poolInfo.ManagedRuntimeVersion
        iisVersion = $( get-itemproperty HKLM:\SOFTWARE\Microsoft\InetStp\  | Select-Object setupstring ).SetupString
        bindings = Get-WebBinding $appName
        webAppNames = (Get-WebApplication -Site $appName)
    }
}

function Generate-ServiceInfo {
    $bindings = @()
    $servicePid = Get-WmiObject -Class Win32_Service -Filter "Name LIKE '$appName'" | Select-Object -ExpandProperty ProcessId
    $tcpPorts = netstat -ano -p TCP | findstr $servicePid
    $udpPorts = netstat -ano -p UDP | findstr $servicePid
    # If netstat finds only a single port, it will return a String. If there are multiple ports, it will return an
    # array of Strings. So if we received a String we wrap it in an array for consistency in the for-loop.
    if ($null -ne $tcpPorts -and $tcpPorts -is [String]) {
        $tcpPorts = @($tcpPorts)
    }
    if ($null -ne $udpPorts -and $udpPorts -is [String]) {
        $udpPorts = @($udpPorts)
    }
    try {
        foreach ($portStr in $tcpPorts + $udpPorts) {
            # Skip empty lines.
            $out = $portStr.Split('') | Where-Object{ $_ -ne "" }
            if ($out.count -gt 0) {
                $LCount = $out[1].LastIndexOf(':')
                $RCount = $out[2].LastIndexOf(':')
                $bindings += [PSCustomObject]@{
                    'Service' = $ProcessName
                    'PID' = $servicePid
                    'Protocol' = $out[0]
                    'LocalAddress' = $out[1].SubString(0, $LCount)
                    'LocalPort' = $out[1].SubString($Lcount + 1, ($out[1].Length - $Lcount - 1))
                    'RemoteAddress' = $out[2].SubString(0, $RCount)
                    'RemotePort' = $out[2].SubString($RCount + 1, ($out[2].Length - $Rcount - 1))
                    'Connection' = $(
                        # Checking if the connection contains any empty string.
                        if (!($out[3] -match '\d')) {
                            $out[3]
                        }
                    )
                }
            }
        }
    } catch {
        $exception = $_.Exception.Message
        New-Message $ErrorMsg "WindowsServiceNetstatError" "Got output: '$mports'. Exception: '$exception'"
        Exit-Application
    }

    $servicePath = Get-WmiObject -Class Win32_Service -Filter "Name LIKE '$appName'" | Select-Object -ExpandProperty PathName | Resolve-Env
    $servicePath = $servicePath.Replace("`"","")
    [PSCustomObject]@{
        bindings = $bindings
        serviceName = $appName
        serviceBinary = $servicePath -split "\\" | Select-Object -Last 1 # Get everything after the last "\"
        serviceDir = ($servicePath | Select-String -pattern '(.+)\\').Matches[0].Value # Get everything before the last "\"
    }
}

function Generate-Template {
    New-Message $InfoMsg "Generating application analysis file..."
    try {
        Create-Dir -path $script:reportFilePath -cleanDir $true
    } catch {
        New-Message $ErrorMsg "CreateReportDirFail" $_.Exception.Message
        Exit-Application
    }
    $appTemplateFile = $script:reportFilePath + "analysis.json"
    $osInfo = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, WindowsDirectory
    $features = Get-WindowsFeature | Where-Object { $_.Installed -match "True" } | Select-Object -Property Name

    $json = [PSCustomObject]@{
        a2CTemplateVersion = $schemaVersion
        createdTime = $(Get-Date -f yyyy-MM-dd-HH:mm:ss)
        containerParameters = [PSCustomObject]@{
            _comment = "*** EDITABLE: The below section can be edited according to the application requirements. Please see the Analysis Results section further below for details discovered regarding the application. ***"
            containerBaseImage = ""
            imageRepositoryName = $appId.ToLower() -replace '\s', '-'
            imageTag = "latest"
            additionalExposedPorts = @()
            appIncludedFiles = @()
            appExcludedFiles = @()
            enableLogging = $false
        }
        analysisInfo = [PSCustomObject]@{
            _comment = "*** NON-EDITABLE: Analysis Results ***"
            hostInfo = [PSCustomObject]@{
                os = $osInfo.Caption
                osVersion = $osInfo.Version
                osWindowsDirectory = $osInfo.WindowsDirectory
                arch = $osInfo.OSArchitecture
            }
            appId = $appId
            appServerIp = "localhost"
            appType = $appType
            appName = $appName
            ports = @() # Port info is handled for each app type.
            features = @(
                foreach ($feature in $features) {
                    if (!($script:defaultImageFeatures.Contains($feature.Name))) {
                        $feature.Name
                    }
                }
            )
        }
    }

    # Add empty list for includedWebApps for IIS sites
    if ($appTypeEnum -eq [AppType]::IIS) {
        $json.containerParameters | Add-Member -MemberType NoteProperty -Name 'includedWebApps' -Value @()
    }

    # Add additional apps at the end
    $json.containerParameters | Add-Member -MemberType NoteProperty -Name 'additionalApps' -Value @()

    if ($appTypeEnum -eq [AppType]::IIS) {
        $iisInfo = Generate-IISInfo

        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'appPoolName' -Value $iisInfo.poolName
        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'poolIdentityType' -Value $iisInfo.poolIdentityType
        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'dotNetVersion' -Value $iisInfo.dotNetVersion
        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'iisVersion' -Value $iisInfo.iisVersion
        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'sitePhysicalPath' -Value $iisInfo.sitePhysicalPath
        $discoveredWebApps = @(
            ForEach ($webapp in $iisInfo.webAppNames) {
                $webAppName = $webapp.Path.Trim('/')
                [PSCustomObject]@{
                    webAppName = $webapp.Path.Trim('/')
                    webAppPool = $webapp.applicationPool
                    webAppPhysicalPath = $webapp.PhysicalPath | Resolve-Env
                    webAppVirtualDirs = $iisInfo.appVirtualDirs[$webAppName]
                }
            }
        )
        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'discoveredWebApps' -Value $discoveredWebApps

        $json.containerParameters.includedWebApps = @(
            ForEach ($webAppName in $iisInfo.webAppNames) {
                $webAppName.Path.Trim('/')
            }
        )

        $json.analysisInfo.ports = @(
            $iisInfo.bindings | ForEach-Object {
                [PSCustomObject]@{
                    localPort = [int]($( $_ | Select-Object -ExpandProperty bindingInformation ) -split ':')[1]
                    protocol = $_ | Select-Object -ExpandProperty protocol
                }
            }
        )

        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'reportPath' -Value $script:reportFile
        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'siteUsesWindowsAuth' -Value $script:siteUsesWindowsAuth

    } elseif ($appTypeEnum -eq [AppType]::Service) {
        $serviceInfo = Generate-ServiceInfo

        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'serviceName' -Value $serviceInfo.serviceName
        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'serviceBinary' -Value $serviceInfo.serviceBinary
        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'serviceDir' -Value $serviceInfo.serviceDir

        $json.analysisInfo.ports = @(
            $serviceInfo.bindings | ForEach-Object {
                [PSCustomObject]@{
                    localPort = [int]($_ | Select-Object -ExpandProperty LocalPort)
                    protocol = $_ | Select-Object -ExpandProperty Protocol
                }
            }
        )
    }
    # only keep unique ports from localPort
    $json.analysisInfo.ports = @($json.analysisInfo.ports | Sort-Object -Property localPort -Unique)
    # Use first port as default applicationPort
    if ($json.analysisInfo.ports.count -eq 0) {
        New-Message $ErrorMsg "errors.AppHasNoPorts"
    } else {
        $json.containerParameters | Add-Member -MemberType NoteProperty -Name 'applicationPort' -Value $json.analysisInfo.ports[0].localPort
    }

    if ($script:backupLocalPath -ne $null -and $appTypeEnum -eq [AppType]::IIS) {
        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'serverBackupFile' -Value $script:backupLocalPath
        $json.containerParameters | Add-Member -MemberType NoteProperty -Name 'enableServerConfigurationUpdates' -Value $true
    } else {
        $json.analysisInfo | Add-Member -MemberType NoteProperty -Name 'serverBackupFile' -Value ""
        $json.containerParameters | Add-Member -MemberType NoteProperty -Name 'enableServerConfigurationUpdates' -Value $false
    }
    $json | ConvertTo-Json -Depth 5 | Format-Json | Out-File $appTemplateFile -Encoding ASCII
    New-Message $InfoMsg "Defaulting to base image: $baseImage. Make changes to the analysis file if an alternative base image is preferred."
    New-Message $InfoMsg "Application analysis file generated at '$appTemplateFile'."
}

try {
    $LASTEXITCODE = $null
    if ( $disableTermNiceties -eq "true" ) {
        $progressPreference = 'silentlyContinue'
    }
    New-Message $InfoMsg "Analyzing web application '$appName'."
    Check-Prerequisites
    Prepare-Inputs
    if ($appTypeEnum -eq [AppType]::IIS) {
        Backup-ServerConfig
    }
    Generate-Template
    if ($appTypeEnum -eq [AppType]::IIS) {
        Prepare-EditableFiles
    }
    New-Message $InfoMsg "After appropriate edits, please proceed with either 'app2container extract' or app2container containerize'."
    New-Message $InfoMsg "Analysis for application: '$appId' completed."
} catch [System.Management.Automation.CommandNotFoundException]{
	$FailedCommand=$_.Exception.CommandName
    New-Message $ErrorMsg "CommandNotFound" "Could not find the command $FailedCommand"
    Exit-Application
} catch [System.Management.Automation.ItemNotFoundException]{
	$ItemName=$_.Exception.ItemName
    New-Message $ErrorMsg "PathNotFound" "Could not find the path $ItemName"
    Exit-Application
} catch [System.UnauthorizedAccessException]{
    New-Message $ErrorMsg "AccessDenied" $_.Exception.Message
    Exit-Application
} catch {
    New-Message $InfoMsg "Internal error occurred. $_.Exception.Message"
    New-Message $ErrorMsg "PSUnknownException" $_.Exception.Message
    Exit-Application
}