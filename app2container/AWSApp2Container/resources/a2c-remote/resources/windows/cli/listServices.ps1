# This script lists the non-default services ie. all services except for default system and application services.
# It runs during `app2container inventory` on Windows hosts.
# Copyright (c) 2021 Amazon Inc. All rights reserved.

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [boolean] $listAll
)

Function List-NonDefaultServices {
    $NonDefaultServices = ""
    if ( $listAll ) {
        $NonDefaultServices = Get-WmiObject -Class Win32_Service | where { `
            $_.State -match "Running" <# Only include running services #>`
        }
    } else {
        $NonDefaultServices = Get-WmiObject -Class Win32_Service | where { `
            $_.State -match "Running" <# Only include running services #>`
            -and $_.PathName -notmatch "System32" <# Exclude System32 dir #>`
            -and $_.PathName -notmatch "\\Windows" <# Exclude C:\Windows dir #>`
            -and $_.PathName -notmatch "Microsoft" <# Exclude C:\Microsoft dir like .Net #>`
            -and $_.PathName -notmatch "SQL Server" <# Exclude DB #>`
            -and $_.PathName -notmatch "Visual Studio" <# Exclude VS #>`
            -and $_.PathName -notmatch "Amazon" <# Exclude Amazon dir like SSM agent #>`
            -and $_.PathName -notmatch "Docker" <# Exclude docker engine #>`
            -and $_.PathName -notmatch "policyhost.exe" <# Exclude Microsoft Policy Platform service #>`
            -and $_.Name -ne "LSM" <# Exclude the Local Session Manager service #>`
            -and $_.PathName -notmatch "OSE.EXE" <# Exclude the Office Source Engine Service #>`
            -and $_.PathName -notmatch "OSPPSVC.EXE" <# Exclude the the Office Software Protection Platform Service #>`
            -and $_.PathName -notmatch "Microsoft Security Client" <# Exclude Microsoft Security Client (SCEP) #>`
        }
    }
    $NonDefaultServices.Name | Write-Output
}
List-NonDefaultServices