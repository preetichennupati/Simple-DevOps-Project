# Copyright 2019, Amazon.com, Inc. or its affiliates. All rights reserved.

<#

.SYNOPSIS
This powershell script will create a CredentialSpec inside the Container Host for a given Group Managed Service Account (GMSA).

.DESCRIPTION
This powershell script will create a CredentialSpec (if not already presnet) for a given Group Managed Service Account (GMSA).
With an optional parameter, if the given GMSA does not exist, it will be created. If the GMSA needs to be created, the script
will need the ADSecurityGroup to grant access to and also the credentials of a domain user that is a part of Domain Admins group.
The script assumes that the Container host is already joined to the domain. If an ADSecurityGroup is provided, the script assumes that it already exists.

The script takes the following parameters
- GMSAName              - [Required] Name of the Group Managed Service Account.
- CreateGMSA            - [Optional] Create GMSA if it does not exist.
- ADSecurityGroup       - [Optional] Name of the AD Security Group for GMSA to grant access to (assumes it exists already).

.EXAMPLE
CreateCredSpecFile.ps1 -GMSAName MyGMSAForIIS
CreateCredSpecFile.ps1 -GMSAName MyGMSAForIIS -CreateGMSA:$true -ADSecurityGroup myIISContainerHosts

.LINK
https://docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/manage-serviceaccounts

.NOTES
In order for Windows Authentication to work inside the Container, the Container host needs to join the Domain, added to the ADSecurityGroup
that's been authorized to retrieve GMSA. This is done as a part of the DomainJoinAddToSecGroup.ps1
This script creates a Credential Spec file for a given GMSA in the container host for docker to use when it runs the container.

#>

#################### SCRIPT PARAMETERS ########################

param(
    [parameter(Mandatory=$true, HelpMessage="Name of the Group Managed Service Account (15 chars or less).")] [ValidateNotNullOrEmpty()] [String] $GMSAName,
    [parameter(Mandatory=$false, HelpMessage="Create GMSA if it does not exist.")] [switch] $CreateGMSA,
    [parameter(Mandatory=$false, HelpMessage="Name of the AD Security Group for GMSA to grant access to (assumes it exists already).")] [ValidateNotNullOrEmpty()] [String] $ADSecurityGroup
)

$ErrorActionPreference = "Stop"
try {
    # Verify that the Host is part of domain
    if (!(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
        Write-Error "Please join the host to Domain before executing this script."
        exit
    }

    if ($GMSAName.length > 15) {
        Write-Error "GMSA: $GMSAName cannot be longer than 15 characters."
        exit
    }

    # Create GMSA if needed
    If (-Not (Get-ADServiceAccount -Filter "Name -eq '$GMSAName'")) {
        if ($CreateGMSA) {
            Write-Host "GMSA: $GMSAName does not exist. Creating ..."
            $ADDomainName = (Get-WmiObject Win32_ComputerSystem).Domain
            if ([string]::IsNullOrEmpty($ADSecurityGroup)) {
                Write-Error "Please provide a valid AD Security Group Name to create GMSA"
                exit
            }
            $DomainUserCred = Get-Credential -Message "Enter Domain User Credentials"
            New-ADServiceAccount -Name $GMSAName -PrincipalsAllowedToRetrieveManagedPassword "$ADSecurityGroup" -DNSHostName $ADDomainName -Credential $DomainUserCred
            Write-Host "GMSA: $GMSAName successfully created!"
		} else {
			Write-Error "GMSA: $GMSAName does not exist. Please use CreateGMSA parameter to create it."
			exit
		}
    }

    # Testing if the host can use the GMSA
    try {
        $Status = Test-ADServiceAccount $GMSAName
    } Catch {
        $Status = $false
    }
    if (!$Status) {
        Write-Warning "The Container host does not seem to have permissions to access the account: $GMSAName."
        Write-Warning "Please ensure that the container host is joined to the correct AD Security Group. A reboot may be necessary after such an operation."
    }

    # Create CredSpecFile
    Write-Host "Creating CredentialSpec File for GMSA: $GMSAName"
    Install-Module CredentialSpec -Force -Confirm:$false -Scope CurrentUser
    $CredSpecFile = New-CredentialSpec -AccountName $GMSAName
    if ($credSpecFile -eq $null) {
        Write-Error "Failed to generate CredentialSpec for account: $GMSAName"
        exit
    }

    Write-Host "CredSpec file successfully generated in $($CredSpecFile.Path)"
    Write-Host "To run container locally, in your docker run command, include: --security-opt `"credentialspec=file://$($CredSpecFile.Name)`""
    Write-Host "To use this in ECS, ensure that dockerSecurityOptions parameter of ecsParameters section inside deployment.json file contains: `"credentialspec:file://$($CredSpecFile.Name)`""
} catch [Exception] {
    Write-Host "Exception while executing the script."
    Write-Host $_.Exception.ToString()
}

# SIG # Begin signature block
# MIIjewYJKoZIhvcNAQcCoIIjbDCCI2gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCoNt1fd46cnZVt
# +8kFu7aoAZODV41kipeG/WDBe6I6faCCEdswggU7MIIDI6ADAgECAgphIE20AAAA
# AAAnMA0GCSqGSIb3DQEBBQUAMH8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xKTAnBgNVBAMTIE1pY3Jvc29mdCBDb2RlIFZlcmlmaWNhdGlvbiBS
# b290MB4XDTExMDQxNTE5NDUzM1oXDTIxMDQxNTE5NTUzM1owbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2UgRVYgUm9vdCBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm+9S75S0tMqbf
# 5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTWPNt0OKRKzE0l
# gvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEMxChBVfvLWokV
# fnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFBIk5lYYeBQVCm
# eVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQNAQTXKFx01p8VdteZOE3hzBWBOURtCmA
# EvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsgEsxBu24LUTi4
# S8sCAwEAAaOByzCByDARBgNVHSAECjAIMAYGBFUdIAAwCwYDVR0PBAQDAgGGMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8G
# A1UdIwQYMBaAFGL7CiFbf0NuEdoJVFBr9dKWcfGeMFUGA1UdHwROMEwwSqBIoEaG
# RGh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY3Jv
# c29mdENvZGVWZXJpZlJvb3QuY3JsMA0GCSqGSIb3DQEBBQUAA4ICAQAgjMFZ7W+c
# ay3BSj51HUVMQVAcvYDq2bCSiwYqEz9TFp5WOWqKY7Z4JHn1fbi5R6EKlsL2y72i
# Zp8G4azSeQkO/TzcrAIMcK8/G+x4ftTrSwVgJtlzYZEh7bBoY+CXEqtvoBLt2Z/S
# 2ic8s+RW+dHUgQ9xvUJ8ponczdW9laKr8ZMRfeisMSmoXWZwQZ38dcnVsxo5KtCF
# BVCLrJHKxJPLcaWdpJRvWAz6biDECDG1hZ1+gfnSPcpbGIVsCobsIgkbpXQ0T38o
# vJVKqx22mLBdCaR3dn7vp45dhPYYJMvRbabDoZzCEHWA/50y/ebPQzqC986P4XIq
# m2K3X+2VGjlcL5RtSLcBXzMvu9wtczSJBEIKHIt5+aP6F+/6oRoQ3+CywZXrXAwF
# lzs1PhiITdtsvySJjci92J97OTokoNXf0fNKGpf2pm96H7CQqbOsATmR02G3ZPE+
# VzgDr8560rWQ9a7cOZnVtjyX7abLFsd9aypMkJTmTFT9Hs0g7M5onIdY6WFgvusO
# ydUZfZ/peL0OrCF1B4+pbuCMaiprnOPnZby8LTxt3ATcZ0U2Mq8EgbyoAG5hTJXF
# XNSOjp8vwTJ0vb0RZQMHze+3XgJX2obUGig0r4hJss+l3YJWb2iqFOJZVP7/6u7v
# 6pJwImCB4yUjwJ/MD0myNapYwzrD2RaUEDCCBdgwggTAoAMCAQICEAFXOd/HbGJW
# 5/RjcoKs8WAwDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTErMCkGA1UE
# AxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEyKTAeFw0xNzA2MDEw
# MDAwMDBaFw0yMDA2MDQxMjAwMDBaMIIBHTEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdh
# bml6YXRpb24xEzARBgsrBgEEAYI3PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMI
# RGVsYXdhcmUxEDAOBgNVBAUTBzQxNTI5NTQxGDAWBgNVBAkTDzQxMCBUZXJyeSBB
# dmUgTjEOMAwGA1UEERMFOTgxMDkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMSIwIAYDVQQKExlBbWF6b24gV2ViIFNl
# cnZpY2VzLCBJbmMuMRQwEgYDVQQLEwtFQzIgV2luZG93czEiMCAGA1UEAxMZQW1h
# em9uIFdlYiBTZXJ2aWNlcywgSW5jLjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBAMhxV81JHePkuhSpVQy3FLg0gmr+o4ZAwadPP3mea2ks4bye/jsbNTHM
# WSqcWYPHGNX0tSgx3nJmFVbJ8Qgy/tGxXRGExmon+u601/C3ev/iG2rEOqJQfA1Q
# q2qgc7DRDapLIoVtrAJRub8F/ev/JrkAJsTP9pvMKK+8my9ChG1+XJ8J6bAXZC4r
# xrDlz3wBv3GXT9kmB373roG/GN/ZVUpZ/mk65Ao2jqdxk5T2C2CTy5XyHnIi20Ww
# k/sqk3+GhdkLzwRlfOOLNK4uG613tMTMFjnot/2rSCJn5HyKJhB16eQoEanvm69S
# pslX6GOd2iGApFnwSdZAVW9WbatoBlMCAwEAAaOCAcEwggG9MB8GA1UdIwQYMBaA
# FI/ofvBtMmoABSPHcJdqOpD/a+rUMB0GA1UdDgQWBBSknbTZwaNKHtI1TDCznDpC
# YT0hhTAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwewYDVR0f
# BHQwcjA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0VWQ29kZVNpZ25p
# bmdTSEEyLWcxLmNybDA3oDWgM4YxaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0VW
# Q29kZVNpZ25pbmdTSEEyLWcxLmNybDBLBgNVHSAERDBCMDcGCWCGSAGG/WwDAjAq
# MCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAcGBWeB
# DAEDMH4GCCsGAQUFBwEBBHIwcDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEgGCCsGAQUFBzAChjxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRFVkNvZGVTaWduaW5nQ0EtU0hBMi5jcnQwDAYDVR0TAQH/BAIw
# ADANBgkqhkiG9w0BAQsFAAOCAQEABOfgvE16qV5sLyP6B5sGLAZhhtzyYz7k1SmZ
# 7lJ0kdew5Cm2mX2OdkVugRUOW2fF8cQy15ssapfmTPvB6q3kelZq1yO8xNNtmuo4
# xNW+ys2BxKMn9VmhpaqYWy7i4e7AdcIfKoVQDkHFKomsyMstg2HlIT9nyNDYEBid
# mFqF62fPs53YignM2BGpIcz85exmtMqzG/6jyo+pQrCG77kcUdL59de+/mJn0w4t
# wpM9lh5yiNuB1kKT6oJi6HJOFJHcBR2VEAcecnIxyQ1SK0SJE1C3FdnxK7XIEXkE
# TEx1QQUAYIfJerfNSDmD7o67ndViYYwk1MgOHvuSnXRvy6wgHjCCBrwwggWkoAMC
# AQICEAPxtOFfOoLxFJZ4s9fYR1wwDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2UgRVYgUm9vdCBD
# QTAeFw0xMjA0MTgxMjAwMDBaFw0yNzA0MTgxMjAwMDBaMGwxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xKzApBgNVBAMTIkRpZ2lDZXJ0IEVWIENvZGUgU2lnbmluZyBDQSAoU0hBMikw
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnU/oPsrUT8WTPhID8roA1
# 0bbXx6MsrBosrPGErDo1EjqSkbpX5MTJ8y+oSDy31m7clyK6UXlhr0MvDbebtEkx
# rkRYPqShlqeHTyN+w2xlJJBVPqHKI3zFQunEemJFm33eY3TLnmMl+ISamq1FT659
# H8gTy3WbyeHhivgLDJj0yj7QRap6HqVYkzY0visuKzFYZrQyEJ+d8FKh7+g+03by
# QFrc+mo9G0utdrCMXO42uoPqMKhM3vELKlhBiK4AiasD0RaCICJ2615UOBJi4dJw
# JNvtH3DSZAmALeK2nc4f8rsh82zb2LMZe4pQn+/sNgpcmrdK0wigOXn93b89Ogkl
# AgMBAAGjggNYMIIDVDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB
# hjATBgNVHSUEDDAKBggrBgEFBQcDAzB/BggrBgEFBQcBAQRzMHEwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBJBggrBgEFBQcwAoY9aHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9v
# dENBLmNydDCBjwYDVR0fBIGHMIGEMECgPqA8hjpodHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlRVZSb290Q0EuY3JsMECgPqA8hjpo
# dHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlRVZS
# b290Q0EuY3JsMIIBxAYDVR0gBIIBuzCCAbcwggGzBglghkgBhv1sAwIwggGkMDoG
# CCsGAQUFBwIBFi5odHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9zc2wtY3BzLXJlcG9z
# aXRvcnkuaHRtMIIBZAYIKwYBBQUHAgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAA
# bwBmACAAdABoAGkAcwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMA
# dABpAHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgA
# ZQAgAEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgA
# ZQAgAFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4A
# dAAgAHcAaABpAGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAA
# YQBuAGQAIABhAHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIA
# ZQBpAG4AIABiAHkAIAByAGUAZgBlAHIAZQBuAGMAZQAuMB0GA1UdDgQWBBSP6H7w
# bTJqAAUjx3CXajqQ/2vq1DAfBgNVHSMEGDAWgBSxPsNpA/i/RwHUmCYaCALvY2Qr
# wzANBgkqhkiG9w0BAQsFAAOCAQEAGTNKDIEzN9utNsnkyTq7tRsueqLi9ENCF56/
# TqFN4bHb6YHdnwHy5IjV6f4J/SHB7F2A0vDWwUPC/ncr2/nXkTPObNWyGTvmLtbJ
# k0+IQI7N4fV+8Q/GWVZy6OtqQb0c1UbVfEnKZjgVwb/gkXB3h9zJjTHJDCmiM+2N
# 4ofNiY0/G//V4BqXi3zabfuoxrI6Zmt7AbPN2KY07BIBq5VYpcRTV6hg5ucCEqC5
# I2SiTbt8gSVkIb7P7kIYQ5e7pTcGr03/JqVNYUvsRkG4Zc64eZ4IlguBjIo7j8eZ
# jKMqbphtXmHGlreKuWEtk7jrDgRD1/X+pvBi1JlqpcHB8GSUgDGCEPYwghDyAgEB
# MIGAMGwxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNV
# BAsTEHd3dy5kaWdpY2VydC5jb20xKzApBgNVBAMTIkRpZ2lDZXJ0IEVWIENvZGUg
# U2lnbmluZyBDQSAoU0hBMikCEAFXOd/HbGJW5/RjcoKs8WAwDQYJYIZIAWUDBAIB
# BQCgfDAQBgorBgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg
# 1xD9LfOxMbnhZ9zS+mgXTnbbExhZepg+hh6WOl9A9HkwDQYJKoZIhvcNAQEBBQAE
# ggEAPIELrGVuEt9BIa57Ydzk8wG0MhXKuaP143A5KuYKEdqN7sLHdXkS7U1LAAf6
# r2SNMf7lHi43hja86BnOZNUIMh4C8Fn5SmmnzOF3F4E/KJuy2CMGRn4JuRR5z4q0
# d80iwCLgjzOlAXuZg6difS4NkHv1SxZ+vxd6SyiCZH/qZtPS+jE+l432NXwTntSB
# WHMndZcUyxjnIMSWC06xF/x7WSHPtJD0U6JJbg2sZBjWwWuWus4robf+a17DuzxN
# 7aTQIE/Nux7qWsl0L1oW1d5qTmZrskPhFemdyBMncG54Jj/9tpV1UForjuFI5hhm
# 42vJayP1T9E2MeEBSmDOXPh0/aGCDsgwgg7EBgorBgEEAYI3AwMBMYIOtDCCDrAG
# CSqGSIb3DQEHAqCCDqEwgg6dAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcN
# AQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCCsMsRx
# oR5hDxxXffur7MJdP97696+3SH7MkQkdaFT4PQIQGxSzqwM5eF7GQH7CtJo3BBgP
# MjAxOTExMjQwMDQwNTRaoIILuzCCBoIwggVqoAMCAQICEATNP4VornbGG7D+cWDM
# p20wDQYJKoZIhvcNAQELBQAwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGln
# aUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQTAeFw0xOTEwMDEw
# MDAwMDBaFw0zMDEwMTcwMDAwMDBaMEwxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjEkMCIGA1UEAxMbVElNRVNUQU1QLVNIQTI1Ni0yMDE5LTEw
# LTE1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6WQ1nPqpmGVkG+QX
# 3LgpNsxnCViFTTDgyf/lOzwRKFCvBzHiXQkYwvaJjGkIBCPgdy2dFeW46KFqjv/U
# rtJ6Fu/4QbUdOXXBzy+nrEV+lG2sAwGZPGI+fnr9RZcxtPq32UI+p1Wb31pPWAKo
# MmkiE76Lgi3GmKtrm7TJ8mURDHQNsvAIlnTE6LJIoqEUpfj64YlwRDuN7/uk9MO5
# vRQs6wwoJyWAqxBLFhJgC2kijE7NxtWyZVkh4HwsEo1wDo+KyuDT17M5d1DQQiwu
# es6cZ3o4d1RA/0+VBCDU68jOhxQI/h2A3dDnK3jqvx9wxu5CFlM2RZtTGUlinXoC
# m5UUowIDAQABo4IDODCCAzQwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAw
# FgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwggG/BgNVHSAEggG2MIIBsjCCAaEGCWCG
# SAGG/WwHATCCAZIwKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNv
# bS9DUFMwggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABvAGYA
# IAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkA
# dAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAA
# RABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAA
# UgBlAGwAeQBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAA
# dwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4A
# ZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkA
# bgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wCwYJYIZIAYb9bAMVMB8GA1Ud
# IwQYMBaAFPS24SAd/imu0uRhpbKiJbLIFzVuMB0GA1UdDgQWBBRWUw/BxgenTdfY
# bldygFBM5OyewTBxBgNVHR8EajBoMDKgMKAuhixodHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vc2hhMi1hc3N1cmVkLXRzLmNybDAyoDCgLoYsaHR0cDovL2NybDQuZGln
# aWNlcnQuY29tL3NoYTItYXNzdXJlZC10cy5jcmwwgYUGCCsGAQUFBwEBBHkwdzAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tME8GCCsGAQUFBzAC
# hkNodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNzdXJl
# ZElEVGltZXN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4IBAQAug6FEBUoE
# 47kyUvrZgfAau/gJjSO5PdiSoeZGHEovbno8Y243F6Mav1gjskOclINOOQmwLOjH
# 4eLM7ct5a87eIwFH7ZVUgeCAexKxrwKGqTpzav74n8GN0SGM5CmCw4oLYAACnR9H
# xJ+0CmhTf1oQpvgi5vhTkjFf2IKDLW0TQq6DwRBOpCT0R5zeDyJyd1x/T+k5mCtX
# kkTX726T2UPHBDNjUTdWnkcEEcOjWFQh2OKOVtdJP1f8Cp8jXnv0lI3dnRq733oq
# ptJFplUMj/ZMivKWz4lG3DGykZCjXzMwYFX1/GswrKHt5EdOM55naii1TcLtW5eC
# +MupCGxTCbT3MIIFMTCCBBmgAwIBAgIQCqEl1tYyG35B5AXaNpfCFTANBgkqhkiG
# 9w0BAQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1
# cmVkIElEIFJvb3QgQ0EwHhcNMTYwMTA3MTIwMDAwWhcNMzEwMTA3MTIwMDAwWjBy
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQg
# SUQgVGltZXN0YW1waW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEAvdAy7kvNj3/dqbqCmcU5VChXtiNKxA4HRTNREH3Q+X1NaH7ntqD0jbOI5Je/
# YyGQmL8TvFfTw+F+CNZqFAA49y4eO+7MpvYyWf5fZT/gm+vjRkcGGlV+Cyd+wKL1
# oODeIj8O/36V+/OjuiI+GKwR5PCZA207hXwJ0+5dyJoLVOOoCXFr4M8iEA91z3Fy
# Tgqt30A6XLdR4aF5FMZNJCMwXbzsPGBqrC8HzP3w6kfZiFBe/WZuVmEnKYmEUeaC
# 50ZQ/ZQqLKfkdT66mA+Ef58xFNat1fJky3seBdCEGXIX8RcG7z3N1k3vBkL9olMq
# T4UdxB08r8/arBD13ays6Vb/kwIDAQABo4IBzjCCAcowHQYDVR0OBBYEFPS24SAd
# /imu0uRhpbKiJbLIFzVuMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgP
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4
# MDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVk
# SURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMFAGA1UdIARJMEcwOAYKYIZIAYb9bAAC
# BDAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAsG
# CWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAQEAcZUS6VGHVmnN793afKpjerN4
# zwY3QITvS4S/ys8DAv3Fp8MOIEIsr3fzKx8MIVoqtwU0HWqumfgnoma/Capg33ak
# OpMP+LLR2HwZYuhegiUexLoceywh4tZbLBQ1QwRostt1AuByx5jWPGTlH0gQGF+J
# OGFNYkYkh2OMkVIsrymJ5Xgf1gsUpYDXEkdws3XVk4WTfraSZ/tTYYmo9WuWwPRY
# aQ18yAGxuSh1t5ljhSKMYcp5lH5Z/IwP42+1ASa2bKXuh1Eh5Fhgm7oMLSttosR+
# u8QlK0cCCHxJrhO24XxCQijGGFbPQTS2Zl22dHv1VjMiLyI2skuiSpXY9aaOUjGC
# Ak0wggJJAgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0
# IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0ECEATNP4VornbGG7D+cWDM
# p20wDQYJYIZIAWUDBAIBBQCggZgwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MBwGCSqGSIb3DQEJBTEPFw0xOTExMjQwMDQwNTRaMCsGCyqGSIb3DQEJEAIMMRww
# GjAYMBYEFAMlvVBe2pYwLcIvT6AeTCi+KDTFMC8GCSqGSIb3DQEJBDEiBCDtYFCp
# WjI5L+IzN+UfZdjuCVxY2w/q1WV9K0mu63yJgzANBgkqhkiG9w0BAQEFAASCAQBP
# AD6i3KEAfBSmZgEpGsILCsnITynP1dEYHx90oiYAEUPCyX4ZtQmgQc0uIH9bhf49
# 5cQCLNQulKDoJKn2OVitNit4ztCvfH6ym1zjRaxHqqOu2Q8281hTrdF8xHBLwWwI
# cMvo/qb2S02W1+ofOxlc7Fgf7HE9gs2nTWnDKaRxzXeL9b4yHSECWIXLDivP913I
# TKMTiFEwQ6L4Irw7mKoHjzYSxqIoytH87uHMgRvWPH521J0lFd0iTWdHDuy7kw1/
# KT1yeAyJr9w6FDmEGd2HWtWurnIolHvrvCaOLTIDdj45QqYVeqOaONRWt0Xf6BmG
# l3ER1oJhwrJH5NqfV5OB
# SIG # End signature block
