[CmdletBinding()]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$hostname=$(throw "Please provide hostname."),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$username=$(throw "Please provide username."),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$password=$(throw "Please provide password."),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("send", "receive", "execute", "create-ps-config", "clean-ps-config")]
    [string]$action=$(throw "Please provide action."),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$certPath=$(throw "Please provide certPath."),

    [Parameter()]
    [string] $command,

    [Parameter()]
    [string] $src,

    [Parameter()]
    [string] $dst,

    [Parameter()]
    [switch] $isDir,

    [Parameter()]
    [string]$psConfigName,

    [Parameter()]
    [string] $logFile
)

# Logging levels
$LevelInfo = "INFO"
$LevelWarn = "WARN"
$LevelErr = "ERROR"

$script:session

function Validate-Inputs {
    if (-Not ([string]::IsNullOrEmpty($logFile))) {
        if (Test-Path $logFile) {
            Write-Log $LevelInfo ("Writting log to {0}" -f $logFile)
        } else {
            # Disable logging if log file doesn't exist
            $logFile = $null
        }
    }
    Switch ($action) {
        {($_ -eq "send") -or ($_ -eq "receive")} {
            if (([string]::IsNullOrEmpty($src))) {
                $errMsg = "Please provide scr path."
                Write-Log $LevelErr $errMsg
                Exit-Application $errMsg
            }
            if (([string]::IsNullOrEmpty($dst))) {
                $errMsg = "Please provide dst path."
                Write-Log $LevelErr $errMsg
                Exit-Application $errMsg
            }
        }
        "execute" {
            if (([string]::IsNullOrEmpty($command))) {
                $errMsg = "Please provide command."
                Write-Log $LevelErr $errMsg
                Exit-Application $errMsg
            }
        }
        {($_ -eq "create-ps-config") -or ($_ -eq "clean-ps-config")} {
            if (([string]::IsNullOrEmpty($psConfigName))) {
                $errMsg = "Please provide powershell configuration name."
                Write-Log $LevelErr $errMsg
                Exit-Application $errMsg
            }
        }
    }
    if (-Not (Test-Path $certPath)) {
        $errMsg = "Cert file does not exist {0}" -f $certPath
        Write-Log $LevelErr $errMsg
        Exit-Application $errMsg
    }
}

function Execute($cmd) {
    if ($cmd) {
        $command = $cmd
    }
    Write-Log $LevelInfo ("Executing command {0} on remote server {1}" -f $command, $hostname)
    try {
        $sb = [scriptblock]::Create($command)
        Invoke-Command -Session $script:session -ScriptBlock $sb
    } catch {
        $errMsg = "Remote command execution failed: {0}" -f $_.Exception.Message
        Write-Log $LevelErr $errMsg
        Exit-Application $errMsg
    }
    Write-Log $LevelInfo ("Remote command executed succussfully")
}

function Send() {
    Write-Log $LevelInfo ("Copying {0} from local server to remote server at {1}" -f $src, $dst)
    try {
        if ($isDir) {
            Copy-Item -Recurse $src -Destination $dst -ToSession $script:session -Force
            Write-Log $LevelInfo ("Folder copied to remote server succussfully")
        } else {
            # Create dir if not exist on remote server
            $cmd = "New-Item -ItemType Directory -Path $dst -Force | out-null"
            Execute $cmd
            Copy-Item $src -Destination $dst -ToSession $script:session -Force
            Write-Log $LevelInfo ("File copied to remote server succussfully")
        }
    } catch {
        $errMsg = "Failed to copy file/folder to remote server: {0}" -f $_.Exception.Message
        Write-Log $LevelErr $errMsg
        Exit-Application $errMsg
    }
}

function Receive() {
    Write-Log $LevelInfo ("Fetching {0} from remote server to local server at {1}" -f $src, $dst)
    try {
        if ($isDir) {
            Copy-Item -Recurse $src -Destination $dst -FromSession $script:session -Force
            Write-Log $LevelInfo ("Folder fetched to local server succussfully")
        } else {
            # Create dir if not exist on local server
            New-Item -ItemType Directory -Path $dst -Force -errorAction stop | out-null
            Copy-Item $src -Destination $dst -FromSession $script:session -Force
            Write-Log $LevelInfo ("File fetched to local server succussfully")
        }
    } catch {
        $errMsg = "Failed to fetch file/folder from remote server: {0}" -f $_.Exception.Message
        Write-Log $LevelErr $errMsg
        Exit-Application $errMsg
    }
}

function Import-Cert() {
    Import-Certificate -FilePath $certPath -CertStoreLocation cert:\LocalMachine\Root -Confirm:$false | Out-Null
}

function Create-Session {
    $secstr = New-Object -TypeName System.Security.SecureString
    $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
    $creds = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
    $sessOps = New-PSSessionOption -SkipCNCheck
    $script:session = New-PSSession -ComputerName $hostname -SessionOption $sessOps -Credential $creds -UseSSL
    if ( $psConfigName -ne "" -and $(Test-ConfigurationExists $psConfigName)) {
        Write-Log $LevelInfo "Found powershell configuration with name $psConfigName, updating session to use it."
        $script:session = New-PSSession -ComputerName $hostname -SessionOption $sessOps -Credential $creds -UseSSL -ConfigurationName $psConfigName
    }
}


function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("INFO", "ERROR", "WARN")]
        [String] $level,

        [Parameter(Mandatory = $true)]
        [String] $message
    )
    if (-Not [string]::IsNullOrEmpty($logFile)) {
        $timeMsg = $((get-date).ToLocalTime()).ToString("yyyy-MM-dd HH:mm:ss")
        $levelMsg = "[" + $level +"]"
        $line = $timeMsg + " - " + "PsOperation" + " - " + $levelMsg + " - " + $message
        Add-Content $logFile $line -Force
    }
}

function Test-ConfigurationExists([String]$configName) {
    $configs = Invoke-Command -Session $script:session -ScriptBlock {
        Param($configName)
        Get-PSSessionConfiguration | Where-Object { $_.Name -like $configName }
    } -ArgumentList $configName
    if ($configs.Count -eq 0) {
        return $false
    } else {
        return $true
    }
}

function Create-PowershellConfiguration {
    $secstr = New-Object -TypeName System.Security.SecureString
    $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
    $creds = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
    if (-not $(Test-ConfigurationExists $psConfigName)) {
        Invoke-Command -Session $script:session -ScriptBlock  {
            Param($configName, $PSCreds)
            Register-PSSessionConfiguration -Name $configName -RunAsCredential $PSCreds
        } -ArgumentList $psConfigName, $creds
        Write-Log $LevelInfo "Successfully created new config with name $psConfigName"
    } else {
        Write-Log $LevelInfo "Powershell config with name $psConfigName already exists"
    }
}

function Remove-PowershellConfiguration([String]$configName) {
    Invoke-Command -Session $script:session -ScriptBlock {
        Param($configName)
        Unregister-PSSessionConfiguration -Name $configName -Force
    } -ArgumentList $configName
}

function Clean-PowershellConfiguration {
    # remove all old configurations
    $maxAge = (Get-Date).AddMinutes(-60)
    $configurations = Invoke-Command -Session $script:session -ScriptBlock {
        Get-PSSessionConfiguration | Where-Object { $_.Name -like "AWS-AppModernization-*" }
    }
    foreach ($configuration in $configurations) {
        $configTimestamp = $configuration.Name -replace "AWS-AppModernization-"
        $creationTime = [DateTime]::ParseExact($configTimestamp, "yyyyMMddHHmmss", $null)
        if ($creationTime -lt $maxAge) {
            Remove-PowershellConfiguration $configuration.Name
        }
    }
    # remove powershell config used for current session
    Remove-PowershellConfiguration $psConfigName
}

function Exit-Application([String]$errMsg) {
    Write-Error $errMsg
    exit 1
}

$LASTEXITCODE = $null
$ErrorActionPreference = 'Stop'

try {
    Validate-Inputs
    Import-Cert
    Create-Session
    Switch ($action) {
        "send" {
            Send
        }
        "receive" {
            Receive
        }
        "execute" {
            Execute
        }
        "create-ps-config" {
            Create-PowershellConfiguration
        }
        "clean-ps-config" {
            Clean-PowershellConfiguration
        }
    }
} catch {
    $errMsg = "PS operation command failed: {0}" -f $_.Exception.Message
    Write-Log $LevelErr $errMsg
    Exit-Application $errMsg
}
