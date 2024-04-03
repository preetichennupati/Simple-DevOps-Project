# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

function Global:Create-Dir([string]$path, [bool]$cleanDir) {
    $dirExist = Test-Path $path
    if($dirExist -and $cleanDir) {
        Remove-Item $path -Recurse -Force | Out-Null
    }
    New-Item -ItemType Directory -Force -Path $path | Out-Null
}

function Resolve-Env {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0,ValueFromPipeline = $True,Mandatory = $True)]
        [string]$String
    )
    #if string contains environment variable then process it
    if ($string -match "%\S+%") {
        $values = $string.split("%") | Where-Object { $_ }
        foreach ($text in $values) {
            # find the corresponding value in ENV:
            [string]$replace = (Get-Item env:$text -ErrorAction "SilentlyContinue").Value
            if ($replace) {
                # if found append it to the new string
                $newString += $replace
            }
            else {
                #otherwise append original string
                $newString += $text
            }
        }
        Write-Output $newString
    }
    else {
        Write-Output $String
    }
}