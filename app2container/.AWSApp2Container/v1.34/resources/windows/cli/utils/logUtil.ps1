# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

$Global:InfoMsg = "Info"

$Global:ErrorMsg = "Error"

$PSDefaultParameterValues['Out-File:Encoding'] = 'ASCII'

function Global:New-Message {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Error", "Debug")]
        [String] $MessageType,

        [Parameter(Mandatory = $true)]
        [String] $ErrorType,

        [Parameter(Mandatory = $false)]
        [String] $ErrorMessage
    )
    if ($MessageType -eq "Error") {
        $errJson = @{ErrorType=$ErrorType;ErrorMessage=$ErrorMessage} | ConvertTo-Json -Compress
        $Host.UI.WriteErrorLine($errJson)
    } elseif ($MessageType -eq "Info"){
        Write-Output $ErrorType
    }
}