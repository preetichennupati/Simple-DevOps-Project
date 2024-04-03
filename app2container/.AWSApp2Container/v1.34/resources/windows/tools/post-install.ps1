# This script runs the post-install steps for AWS App2Container
# It runs after install.ps1 and during 'app2container upgrade'
# Copyright (c) 2019 Amazon Inc. All rights reserved.

$script:ApplicationName = "AWSApp2Container"
$script:PrefixPath = Join-Path -Path "$env:USERPROFILE" -ChildPath "app2container"
$script:InstallPath = Join-Path -Path "$script:PrefixPath" -ChildPath ($script:ApplicationName)
$script:InitFilePath = "$env:LOCALAPPDATA\.app2container-config\app2container.conf"

Function Setup-AutoComplete
{
# If this function is updated make sure the Clear-AutoComplete in uninstall.ps1 works properly
    try {
        Write-Host
        Write-Host "Setting up powershell auto completion for the CLI..."

        if (!(Test-Path -Path "$profile")) {
            New-Item -ItemType File -Path "$profile" -Force | Out-Null
        }
        $ExistingProfile = Get-Content -Path "$profile"
        $CompletionsPath = Join-Path -Path "$script:InstallPath" -ChildPath "resources\windows\tools\app2containercompletions.ps1"
        $NewProfileContent = "`nif (Test-Path '$CompletionsPath' -PathType Leaf) {
        . '$CompletionsPath'
    }`n"
        $escapedContent = [regex]::Escape($CompletionsPath)

        # Uncomment along with last line in app2containercompletions.ps1 for suggestion autocomplete features rather than toggle
        #    If(-not(Get-InstalledModule psreadline -ErrorAction silentlycontinue)){
        #        Install-Module psreadline -Confirm:$False -Force | Out-Null
        #    }

        if (($ExistingProfile -eq $null) -Or (-Not [regex]::Escape($ExistingProfile).Contains($escapedContent))) {
            Write-Host "Adding auto completions to User profile"
            Add-Content -Path $profile -Value "$NewProfileContent"
            # Add to current session
            . "$CompletionsPath"
        }
    } catch {
        Write-Host "Auto completion for the CLI setup failed. Silently continuing installation."
    }
}

Function CheckUploadLogsPermission
{
    $InitJson = $(Get-Content $script:InitFilePath -raw | ConvertFrom-Json)
    # If interactive shell, run interactive post-install commands
    if (-not (Test-IsNonInteractiveShell)) {
        if (-not ($InitJson.PSObject.Properties.Name -contains "supportBundleUploadPermission")) {
            $confirmation = Read-Host "New Feature: Automatically upload logs and App2Container generated artifacts on crashes and internal errors? (Y/N) [Y]"
            if ($confirmation -eq 'n' -or $confirmation -eq 'N') {
                $InitJson | Add-Member -MemberType NoteProperty -Name 'supportBundleUploadPermission' -Value $false
            } else {
                $InitJson | Add-Member -MemberType NoteProperty -Name 'supportBundleUploadPermission' -Value $true
            }
            $InitJson | ConvertTo-Json -Compress -Depth 32 | Set-Content $script:InitFilePath
        }
    }
}

Function PostUpgrade
{
    if (Test-Path $script:InitFilePath -PathType Leaf) {
        CheckUploadLogsPermission
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force | Out-Null
}

function Test-IsNonInteractiveShell
{
    foreach ($arg in [Environment]::GetCommandLineArgs()) {
        # Test each Arg for match of abbreviated '-NonInteractive' command.
        if ($arg -like '-NonI*') {
            return $true
        }
    }

    return $false
}

Function Post-Installer
{
    Setup-AutoComplete
    PostUpgrade
}

Post-Installer
