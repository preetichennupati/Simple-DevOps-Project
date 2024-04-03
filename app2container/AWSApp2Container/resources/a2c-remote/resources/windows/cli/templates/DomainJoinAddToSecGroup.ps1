# Copyright 2019, Amazon.com, Inc. or its affiliates. All rights reserved.

<#

.SYNOPSIS
This powershell script will join the container host to a Domain and adds the host to an AD Security Group.

.DESCRIPTION
This powershell script will join the machine (if not already joined) on which this is being executed (typically the Container Host), to an AD Domain.
It then adds the host to an AD Security Group. Given an option, it also creates that AD Security Group before joining.
In order to carry out the above operations, the script needs credentials of a domain user that is part of Domain Admins group.

The script takes the following parameters
- ADDomainName          - [Optional] Your Domain Name (Required for Domain Join)
- ADDNSIp               - [Optional] IP Address of Active Directory DNS Server (Required for Domain Join)
- ADSecurityGroup       - [Required] Name of the AD Security Group to add this host to. See CreateADSecurityGroup parameter to automatically create it.
- CreateADSecurityGroup - [Optional] Create the ADSecurityGroup if it does not exist.
- Silent                - [Optional] Suppress prompts.

.EXAMPLE
DomainJoinAddToSecGroup.ps1 -ADDomainName CompanyDomain.com -ADDNSIp 10.0.0.1 -ADSecurityGroup myIISContainerHosts
DomainJoinAddToSecGroup.ps1 -ADDomainName CompanyDomain.com -ADDNSIp 10.0.0.1 -ADSecurityGroup myIISContainerHosts -CreateADSecurityGroup:$true
DomainJoinAddToSecGroup.ps1 -ADSecurityGroup myIISContainerHosts

.LINK
https://docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/manage-serviceaccounts

.NOTES
In order for Windows Authentication to work inside the Container, the Container host needs to join the Domain, added to the ADSecurityGroup
that's been authorized to retrieve a Group Managed Service Account (GMSA).

#>

#################### SCRIPT PARAMETERS ########################

param(
    [parameter(Mandatory=$false, HelpMessage="Active Directory Domain Name (For domain join).")] [ValidateNotNullOrEmpty()] [String] $ADDomainName,
    [parameter(Mandatory=$false, HelpMessage="IP Address of Active Directory DNS Server (For domain join).")] [ValidateNotNullOrEmpty()] [String] $ADDNSIp,
    [parameter(Mandatory=$true, HelpMessage="Name of the AD Security Group to add this host to.")] [ValidateNotNullOrEmpty()] [String] $ADSecurityGroup,
    [parameter(Mandatory=$false, HelpMessage="Create the ADSecurityGroup if it does not exist")] [switch] $CreateADSecurityGroup,
    [parameter(Mandatory=$false, HelpMessage="Suppress Prompts")] [switch] $Silent
)

$ErrorActionPreference = "Stop"
try {
    $DomainUserCred = Get-Credential -Message "Enter Domain User Credentials"

    # First check if the Host is already a part of the given Domain

    if (!(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
        # Add the DNS Ip to existing list of DNS Client Server Addresses
        $DNSServerAddressList = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | Select-Object -First 1
        $DNSIpString = $DNSServerAddressList.ServerAddresses -join ","

        # Set up the IPv4 address of the AD DNS server as the first DNS server on this machine
        $UpdatedDNSIpStrings = $("{0},{1}" -f $ADDNSIp, $DNSIpString)
        Write-Host "Adding Updated set of AD DNS server addresses: $UpdatedDNSIpStrings to the IPV4 interface Index: $($DNSServerAddressList.InterfaceIndex)."
        Set-DnsClientServerAddress -InterfaceIndex $DNSServerAddressList.InterfaceIndex -ServerAddresses $UpdatedDNSIpStrings

        # Join the AD domain
        Write-Host "Joining Host: $(hostname) to Domain: $ADDomainName"
        Add-Computer -DomainName $ADDomainName -Credential $DomainUserCred
    } else {
        Write-Host "Host: $(hostname) is already joined to Domain"
    }

    # Install AD Module to invoke Create/Join AD Security Group
    Write-Host "Installing AD Powershell"
    Install-WindowsFeature RSAT-AD-PowerShell

    $ADComputer = Get-ADComputer -Filter "Name -eq `"$(hostname)`"" -Credential $DomainUserCred

    # Add Host to AD Security Group
    $ADSecGroup = Get-ADGroup -Filter "Name -eq `"$ADSecurityGroup`"" -Credential $DomainUserCred
    if ($ADSecGroup -eq $null) {
        if ($CreateADSecurityGroup) {
            Write-Host "AD Security Group: $ADSecurityGroup does not exist. Creating..."
            $ADSecGroup = New-ADGroup -Name $ADSecurityGroup -SamAccountName $ADSecurityGroup -GroupScope DomainLocal -Credential $DomainUserCred -PassThru
        } else {
            Write-Error "AD Security Group: $ADSecurityGroup does not exist. Please use CreateADSecurityGroup parameter to create it."
            exit
        }
	}
    Write-Host "Adding host $($ADComputer.DistinguishedName) to the AD security group $ADSecurityGroup"
    Add-ADGroupMember -Identity $ADSecGroup -Members $ADComputer.DistinguishedName -Credential $DomainUserCred

    Write-Host "Successfully joined $(hostname) to $ADSecGroup"
    Write-Host "Domain Join/Adding Host to Security Group requires a Restart."
    if (!$Silent) {
        $Conf = Read-Host "Would you like to Restart (y/n)?"
    }
    if ($Silent -Or ($Conf -eq "y")) {
        Write-Host "Restarting..."
        Restart-Computer -Force
    } else {
        Write-Host "Please restart manually for changes to take effect"
    }

} catch [Exception] {
    Write-Host "Exception while executing the script."
    Write-Host $_.Exception.ToString()
}

# SIG # Begin signature block
# MIIjfAYJKoZIhvcNAQcCoIIjbTCCI2kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCaEsSkiHBwHYPv
# lzNCxrEp0L5FYQ6/oNu/6abrQkGNa6CCEdswggU7MIIDI6ADAgECAgphIE20AAAA
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
# jKMqbphtXmHGlreKuWEtk7jrDgRD1/X+pvBi1JlqpcHB8GSUgDGCEPcwghDzAgEB
# MIGAMGwxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNV
# BAsTEHd3dy5kaWdpY2VydC5jb20xKzApBgNVBAMTIkRpZ2lDZXJ0IEVWIENvZGUg
# U2lnbmluZyBDQSAoU0hBMikCEAFXOd/HbGJW5/RjcoKs8WAwDQYJYIZIAWUDBAIB
# BQCgfDAQBgorBgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg
# 9v/dGm+VrD6SMWPYzpH5pFS19WCfINSBc36sxFRlffMwDQYJKoZIhvcNAQEBBQAE
# ggEAqoucSx83dxp143xkzQsrDlSplAIVcjPpl6qzDW3VQXSCgJzSS8WHU/q3knV6
# pzb2erxbjSOPGmNj80C4Sm2ZeMoJE4QK+4RXNMbBYHMh5UMRIRawt5U1jswLJ7RJ
# sHINkBCy6uRayiwpCHECa0pDiEL0Ug2nDvSCvc1DwVqIv9tRl2SmnZiKeZ8hL9q4
# E0uDMxv/AaR27g6qFiMalBTavzj4PF3gU0jxVEV3FOZKvwkMR84GATyLpmYf7Gy9
# zRAW0zTGhI7bN2PJvd12JAydgGK8vIgiwOSZ0TPefXt0/z+BUQE0Xr6tZNbbxnZQ
# nbU0BRsMCgNp6QaqhKU35W1226GCDskwgg7FBgorBgEEAYI3AwMBMYIOtTCCDrEG
# CSqGSIb3DQEHAqCCDqIwgg6eAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZIhvcN
# AQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCALpRpF
# cMIJdYHJ7Ah6S2XcgdQiICawzuM7uFYKNtSZOAIRAJ0o406KRnuMwncjjf8zgNAY
# DzIwMTkxMTI0MDA0MDU1WqCCC7swggaCMIIFaqADAgECAhAEzT+FaK52xhuw/nFg
# zKdtMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERp
# Z2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0EwHhcNMTkxMDAx
# MDAwMDAwWhcNMzAxMDE3MDAwMDAwWjBMMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xJDAiBgNVBAMTG1RJTUVTVEFNUC1TSEEyNTYtMjAxOS0x
# MC0xNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOlkNZz6qZhlZBvk
# F9y4KTbMZwlYhU0w4Mn/5Ts8EShQrwcx4l0JGML2iYxpCAQj4HctnRXluOihao7/
# 1K7Sehbv+EG1HTl1wc8vp6xFfpRtrAMBmTxiPn56/UWXMbT6t9lCPqdVm99aT1gC
# qDJpIhO+i4Itxpira5u0yfJlEQx0DbLwCJZ0xOiySKKhFKX4+uGJcEQ7je/7pPTD
# ub0ULOsMKCclgKsQSxYSYAtpIoxOzcbVsmVZIeB8LBKNcA6Pisrg09ezOXdQ0EIs
# LnrOnGd6OHdUQP9PlQQg1OvIzocUCP4dgN3Q5yt46r8fcMbuQhZTNkWbUxlJYp16
# ApuVFKMCAwEAAaOCAzgwggM0MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAA
# MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIIBvwYDVR0gBIIBtjCCAbIwggGhBglg
# hkgBhv1sBwEwggGSMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5j
# b20vQ1BTMIIBZAYIKwYBBQUHAgIwggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBm
# ACAAdABoAGkAcwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABp
# AHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAg
# AEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAg
# AFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAg
# AHcAaABpAGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBu
# AGQAIABhAHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBp
# AG4AIABiAHkAIAByAGUAZgBlAHIAZQBuAGMAZQAuMAsGCWCGSAGG/WwDFTAfBgNV
# HSMEGDAWgBT0tuEgHf4prtLkYaWyoiWyyBc1bjAdBgNVHQ4EFgQUVlMPwcYHp03X
# 2G5XcoBQTOTsnsEwcQYDVR0fBGowaDAyoDCgLoYsaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL3NoYTItYXNzdXJlZC10cy5jcmwwMqAwoC6GLGh0dHA6Ly9jcmw0LmRp
# Z2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtdHMuY3JsMIGFBggrBgEFBQcBAQR5MHcw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBPBggrBgEFBQcw
# AoZDaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3Vy
# ZWRJRFRpbWVzdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAQEALoOhRAVK
# BOO5MlL62YHwGrv4CY0juT3YkqHmRhxKL256PGNuNxejGr9YI7JDnJSDTjkJsCzo
# x+HizO3LeWvO3iMBR+2VVIHggHsSsa8Chqk6c2r++J/BjdEhjOQpgsOKC2AAAp0f
# R8SftApoU39aEKb4Iub4U5IxX9iCgy1tE0Kug8EQTqQk9Eec3g8icndcf0/pOZgr
# V5JE1+9uk9lDxwQzY1E3Vp5HBBHDo1hUIdjijlbXST9X/AqfI1579JSN3Z0au996
# KqbSRaZVDI/2TIryls+JRtwxspGQo18zMGBV9fxrMKyh7eRHTjOeZ2ootU3C7VuX
# gvjLqQhsUwm09zCCBTEwggQZoAMCAQICEAqhJdbWMht+QeQF2jaXwhUwDQYJKoZI
# hvcNAQELBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNz
# dXJlZCBJRCBSb290IENBMB4XDTE2MDEwNzEyMDAwMFoXDTMxMDEwNzEyMDAwMFow
# cjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVk
# IElEIFRpbWVzdGFtcGluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAL3QMu5LzY9/3am6gpnFOVQoV7YjSsQOB0UzURB90Pl9TWh+57ag9I2ziOSX
# v2MhkJi/E7xX08PhfgjWahQAOPcuHjvuzKb2Mln+X2U/4Jvr40ZHBhpVfgsnfsCi
# 9aDg3iI/Dv9+lfvzo7oiPhisEeTwmQNtO4V8CdPuXciaC1TjqAlxa+DPIhAPdc9x
# ck4Krd9AOly3UeGheRTGTSQjMF287DxgaqwvB8z98OpH2YhQXv1mblZhJymJhFHm
# gudGUP2UKiyn5HU+upgPhH+fMRTWrdXyZMt7HgXQhBlyF/EXBu89zdZN7wZC/aJT
# Kk+FHcQdPK/P2qwQ9d2srOlW/5MCAwEAAaOCAc4wggHKMB0GA1UdDgQWBBT0tuEg
# Hf4prtLkYaWyoiWyyBc1bjAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823I
# DzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAK
# BggrBgEFBQcDCDB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0fBHow
# eDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBQBgNVHSAESTBHMDgGCmCGSAGG/WwA
# AgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAL
# BglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggEBAHGVEulRh1Zpze/d2nyqY3qz
# eM8GN0CE70uEv8rPAwL9xafDDiBCLK938ysfDCFaKrcFNB1qrpn4J6JmvwmqYN92
# pDqTD/iy0dh8GWLoXoIlHsS6HHssIeLWWywUNUMEaLLbdQLgcseY1jxk5R9IEBhf
# iThhTWJGJIdjjJFSLK8pieV4H9YLFKWA1xJHcLN11ZOFk362kmf7U2GJqPVrlsD0
# WGkNfMgBsbkodbeZY4UijGHKeZR+WfyMD+NvtQEmtmyl7odRIeRYYJu6DC0rbaLE
# frvEJStHAgh8Sa4TtuF8QkIoxhhWz0E0tmZdtnR79VYzIi8iNrJLokqV2PWmjlIx
# ggJNMIICSQIBATCBhjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2Vy
# dCBTSEEyIEFzc3VyZWQgSUQgVGltZXN0YW1waW5nIENBAhAEzT+FaK52xhuw/nFg
# zKdtMA0GCWCGSAFlAwQCAQUAoIGYMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAcBgkqhkiG9w0BCQUxDxcNMTkxMTI0MDA0MDU1WjArBgsqhkiG9w0BCRACDDEc
# MBowGDAWBBQDJb1QXtqWMC3CL0+gHkwovig0xTAvBgkqhkiG9w0BCQQxIgQg1FP6
# s251WvFEDu5GohWu5jWHgO2FvNCCfvIe85GFgOAwDQYJKoZIhvcNAQEBBQAEggEA
# QeRfRbZoEHIc1rEz4Z7ynQoafStKnVxzTO7sjTm8Gy08Hf5IQy5QD/HHNittSzfa
# Do95CFkLBE6+35/8eXXpNZhSRdCGFctOxEj5BxS9WWksejQ2MN5GaKbR/HBoY9oN
# cuI6iohC44+Cz4/WbBITmstR4RfEyL9Pm/XgezAYazQ1l/NpzrJ5GQLQ4yxRqlZH
# Ma4OV/YHicb7ow85sTmE+9oJowK9rf0i2lZIeU4rz1gXYq3fMqZmdDdtpeIJueZF
# 9dorSm1onWjeHenzpKeGqgQW6LpSh4XnMNpa7xi+CKLLXxMXryLG/hRnhBGjBPx2
# U5Ak3eBm2sMsfzoOi8mn1w==
# SIG # End signature block
