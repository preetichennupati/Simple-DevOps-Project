# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

[CmdletBinding()]
param (
    # Path to analysis.json
    [Parameter(Mandatory = $true)]
    [string] $inputScript,

    [Parameter(Mandatory = $true)]
    [string] $workspacePath,

    [Parameter(Mandatory = $true)]
    [string] $appId,

    # Either IIS or Service
    [Parameter(Mandatory = $true)]
    [string] $appType,

    [Parameter(Mandatory = $false)]
    [string] $profileName,

    [Parameter(Mandatory = $false)]
    [string] $ipRegion,

    [Parameter(Mandatory = $false)]
    [string] $s3BucketName,

    # When handling additional IIS Sites, we recurse and call extract.ps1 again,
    # with this parameter set to the original main app's ID.
    [Parameter(Mandatory = $false)]
    [string] $mainAppId
)

enum AppType {
    Unknown
    IIS
    Service
}

[AppType] $script:mainAppType = [AppType]::Unknown

Import-module "$PSScriptRoot\utils\logUtil.ps1" -Force

Import-module "$PSScriptRoot\utils\jsonUtil.ps1" -Force

Import-module "$PSScriptRoot\utils\pathUtil.ps1" -Force

Import-module "$PSScriptRoot\utils\errorUtil.ps1" -Force

$inputTable = @{
    siteName = ""
    siteUsesWindowsAuth = ""
    containerBaseImage = ""
    enableServerConfigurationUpdates = ""
    imageRepositoryName = ""
    imageTag = ""
    additionalExposedPorts = @()
    appIncludedFiles = @()
    enableLogging = ""
    sitePhysicalPath = ""
    includedWebApps = @()
    appExcludedFiles = @()
    additionalApps = @()
    discoveredWebApps = @()
    features = @()
    serverBackupFile = ""
    serviceName = ""
    serviceBinary = ""
    serviceDir = ""
}

$script:commandType = "Extract"

$script:wdInstallerPath = "$PSScriptRoot\..\tools\WebDeploy_amd64_en-US.msi"

$script:uploadToS3 = $false

$script:DepTypeWindowsService = "WindowsService"

function Check-Prerequisites {
    New-Message $InfoMsg "Checking prerequisites..."
    $psVersion = $PSVersionTable.PSVersion.Major
    if ($psVersion -lt 5) {
        New-Message $ErrorMsg "PSVersionCheckError" "Current PowerShell Version: $psVersion"
        Exit-Application
    }
    if ([Environment]::Is64BitProcess -ne $True) {
        New-Message $ErrorMsg "PSIsNot64BitProcess"
        Exit-Application
    }
    if ($script:s3BucketName -eq "") {
        New-Message $InfoMsg "Skipping AWSPowerShell Module check"
    } elseif ($null -eq (Get-Module -Name AWSPowerShell -ListAvailable)) {
        New-Message $ErrorMsg "AwsPSModuleNotInst"
        Exit-Application
    }
    if ($appType -eq "IIS") {
        $script:mainAppType = [AppType]::IIS
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
        $script:mainAppType = [AppType]::Service
    } else {
        New-Message $ErrorMsg "InvalidAppType" "$appType"
        Exit-Application
    }
}

function Prepare-Inputs {
    $workspacePath | Resolve-Env
    if (-not (Test-Path $workspacePath)) {
        New-Message $ErrorMsg "ValidWorkspaceReq" "Current Path: $workspacePath"
        Exit-Application
    }
    if(!(Test-Path $inputScript)) {
        New-Message $ErrorMsg "AnalysisNotRun"
        Exit-Application
    }
    try {
        if ($inputScript) {
            $script:inputScriptFile = Get-Content $inputScript | Out-String | ConvertFrom-Json
        }
    } catch {
        New-Message $ErrorMsg "JsonValidationFailed" $_.Exception.Message
        Exit-Application
    }
    if (-Not $inputScript.Contains($appId)) {
        New-Message $ErrorMsg "MismatchAnalysisJson" "AppId was not provided: $appId"
        Exit-Application
    }
    $analysisInfo = $inputScriptFile.analysisInfo
    $containerParameters = $inputScriptFile.containerParameters
    if ((-Not $analysisInfo) -or (-Not $containerParameters)) {
        New-Message $ErrorMsg "InvalidJsonFormat"
        Exit-Application
    }

    if ($script:mainAppType -eq [AppType]::IIS) {
        $inputTable.siteName = $analysisInfo.appName
        $siteName = $inputTable.siteName
        if ((-Not $inputTable.siteName -or -Not (Get-Website | Where-Object { $_.name -eq $inputTable.siteName } ))) {
            New-Message $ErrorMsg "IISSiteNotFound" "SiteName:$siteName"
            Exit-Application
        }
        $inputTable.siteUsesWindowsAuth = $analysisInfo.siteUsesWindowsAuth
        if ($inputTable.siteUsesWindowsAuth -ne "") {
            $inputTable.siteUsesWindowsAuth = [System.Convert]::ToBoolean($inputTable.siteUsesWindowsAuth)
        }else{
            $isSiteUsingWindowsAuth = $analysisInfo.isSiteUsingWindowsAuth
            if ($isSiteUsingWindowsAuth -ne ""){
                New-Message $InfoMsg "WARNING: analysis.json has parameter isSiteUsingWindowsAuth, please rerun analyze to update analysis.json"
            }
        }

        $inputTable.sitePhysicalPath = $analysisInfo.sitePhysicalPath
        if ((-Not $inputTable.sitePhysicalPath)) {
            New-Message $ErrorMsg "SitePhysPathNotFound"
            Exit-Application
        }

        $inputTable.serverBackupFile = $analysisInfo.serverBackupFile
        $inputTable.discoveredWebApps = $analysisInfo.discoveredWebApps

    } elseif($script:mainAppType -eq [AppType]::Service) {
        $inputTable.serviceName = $analysisInfo.serviceName
        if (-Not $inputTable.serviceName) {
            New-Message $ErrorMsg "WindowsServiceNotFound"
        }

        $inputTable.serviceBinary = $analysisInfo.serviceBinary
        if (-Not $inputTable.serviceBinary) {
            New-Message $ErrorMsg "WindowsServiceBinaryNotFound"
        }

        $inputTable.serviceDir = $analysisInfo.serviceDir
        if (-Not $inputTable.serviceDir) {
            New-Message $ErrorMsg "WindowsServiceDirNotFound"
        }
    }

    try {
        $inputTable.enableServerConfigurationUpdates  = [System.Convert]::ToBoolean($containerParameters.enableServerConfigurationUpdates)
    } catch [FormatException] {
        $inputTable.enableServerConfigurationUpdates  = $false
    }
    $inputTable.enableServerConfigurationUpdates = $containerParameters.enableServerConfigurationUpdates
    if ($inputTable.enableServerConfigurationUpdates -and ($($inputTable.enableServerConfigurationUpdates) -ieq "true")) {
        $inputTable.enableServerConfigurationUpdates = $true
    } else {
        $inputTable.enableServerConfigurationUpdates = $false
    }
    if ($mainAppId) {
        $script:artifactPath = $workspacePath + "\" + $mainAppId + "\Artifacts\"
    } else {
        $script:artifactPath = $workspacePath + "\" + $appId + "\Artifacts\"
    }
    $inputTable.imageRepositoryName = $containerParameters.imageRepositoryName
    if ((-Not $inputTable.imageRepositoryName)) {
        $inputTable.imageRepositoryName = $inputTable.siteName
    }
    $inputTable.imageTag = $containerParameters.imageTag
    if ((-Not $inputTable.imageTag)) {
        $inputTable.imageTag = "latest"
    }
    $inputTable.additionalExposedPorts = $containerParameters.additionalExposedPorts
    $inputTable.appIncludedFiles = $containerParameters.appIncludedFiles
    $inputTable.includedWebApps = $containerParameters.includedWebApps
    $inputTable.appExcludedFiles = $containerParameters.appExcludedFiles
    $inputTable.additionalApps = $containerParameters.additionalApps

    $inputTable.features = $analysisInfo.features
    if ($profileName -and $s3BucketName) {
        $script:uploadToS3 = $true
        $profileExist = Get-AWSCredential -ProfileName $profileName
        if (!$profileExist -or ($LASTEXITCODE -and ($LASTEXITCODE -ne 0))) {
            New-Message $ErrorMsg "AWSPreReqFailed"
            Exit-Application
        }
        try {
            $profileRegion = "profile." + $profileName + ".region"
            $getRegionCmd = "aws configure get $profileRegion"
            $region = Invoke-Expression -Command $getRegionCmd
            if ($LASTEXITCODE -and ($LASTEXITCODE -ne 0)) {
                New-Message $InfoMsg "Error getting aws region from profile."
            }
            Set-DefaultAWSRegion $region -Scope Global
        } catch{
            New-Message $InfoMsg "Error setting default aws region. continuing..."
        }
    } elseif ($s3BucketName) {
        if (-Not $ipRegion) {
            New-Message $ErrorMsg "Region must be provided when using Instance profile."
            Exit-Application
        }
        # Use Instance Profile (SDK retrieves creds automatically)
        Set-DefaultAWSRegion $ipRegion -Scope Global
        $script:uploadToS3 = $true
    }
    try {
        $inputTable.enableLogging  = [System.Convert]::ToBoolean($containerParameters.enableLogging)
    } catch [FormatException] {
        $inputTable.enableLogging  = $false
    }
}

function Copy-Artifact {
    if ($script:mainAppType -eq [AppType]::IIS) {
        Copy-IISArtifact
    } elseif ($script:mainAppType -eq [AppType]::Service) {
        Copy-ServiceArtifact
    }
}

function Copy-IISArtifact {
    New-Message $InfoMsg "Copying artifacts..."
    CopyDir $inputTable.sitePhysicalPath $script:artifactPath
    foreach ($webApp in $($inputTable.discoveredWebApps)) {
        if ($($inputTable.includedWebApps) -NotContains $webApp.webAppName) {
            continue
        }
        if ($webApp.webAppPhysicalPath) {
           CopyDir $webApp.webAppPhysicalPath $script:artifactPath
        }
        if ($webApp.webAppVirtualDirs) {
            foreach ($vDir in $($webApp.webAppVirtualDirs)) {
                CopyDir $($vDir.dirPath) $script:artifactPath
            }
        }
    }

    if ($inputTable.enableServerConfigurationUpdates) {
        if (($inputTable.serverBackupFile -eq $null) -or ($inputTable.serverBackupFile -eq "")) {
            New-Message $InfoMsg "Warning: Unable to locate serverBackupFile, skipping Server Config Updates"
        } elseif ([Environment]::Is64BitProcess) {
            Copy-Item -Path $script:wdInstallerPath -Destination $script:artifactPath -Force
            Copy-Item -Path $inputTable.serverBackupFile -Destination $script:artifactPath -Force
        }
    }

    New-Message $InfoMsg "Artifact copied: '$script:artifactPath'."
}

function Copy-ServiceArtifact {
    New-Message $InfoMsg "Copying artifacts..."
    Copy-WindowsService $inputTable.serviceName $inputTable.serviceBinary $inputTable.serviceDir
}

# copy srcRootFolder to dstRootFolder, skipping any files that are in appExcludedFiles
function CopyDir([string] $srcRootFolder, [string] $dstRootFolder) {
    if (Test-Path $srcRootFolder) {
        # Create empty folder for root site in dstRootFolder
        $leaf = Split-Path -Path $srcRootFolder -Leaf
        $dstSitePath = Join-Path -Path $dstRootFolder -ChildPath $leaf
        Create-Dir -path $dstSitePath -cleanDir $true

        $srcP = (get-item $srcRootFolder).Parent.FullName
        Push-Location $srcP
        $files = Get-ChildItem -Path $srcRootFolder -Recurse
        foreach($file in $files) {
            if (-not $file.PSIsContainer) {
                $filePath = $file.FullName
                if ($inputTable.appExcludedFiles -and $inputTable.appExcludedFiles.Contains($filePath)) {
                    New-Message $InfoMsg "'$filePath' excluded."
                } else {
                    $relPath = Get-Item $filePath | Resolve-Path -Relative
                    $dstPath = Join-Path -Path $dstRootFolder -ChildPath $relPath
                    $dstFolder = split-Path -Path $dstPath -Parent
                    if (!(Test-Path -path $dstFolder)) {
                        New-Item $dstFolder -Type Directory
                    }
                    Copy-Item -Path $filePath -Destination $dstPath -Force
                }
            }
        }
        Pop-Location
    }
}


function Update-Artifact {
    New-Message $InfoMsg "Updating Artifact..."
    # Copy all editable files to artifact folder.
    if ($script:mainAppType -eq [AppType]::IIS) {
        New-Message $InfoMsg "Processing editable files..."
        Copy-EditableFiles
    }
    # Handle included files.
    New-Message $InfoMsg "Processing included files..."
    Copy-IncludedFiles
    # Handle additional applications.
    New-Message $InfoMsg "Processing additional applications..."
    Copy-AdditionalApps
}

function Copy-EditableFiles {
    $editableFilePath = $workspacePath + "\" + $appId + "\EditableFiles\"
    #Copy site
    $siteName = $inputTable.siteName
    $site = Get-Website -Name $siteName
    if (($site) -and (Test-Path $site.physicalPath)) {
        $leaf = Split-Path -Path $site.physicalPath -Leaf
        $path = "$editableFilePath\$leaf"
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Recurse
            foreach($file in $files) {
                if (-not $file.PSIsContainer) {
                    $sfName =  $file.Name.toString()
                    $sfDir = $file.Directory.toString()
                    $sFile = $sfDir + "\" + $sfName
                    $tFile = $sFile -replace 'EditableFiles','Artifacts'
                    if ($mainAppId) {
                        $tFile = $tFile -replace $appId,$mainAppId
                    }
                    if (!(Test-Path $tFile)) {
                        New-Message $InfoMsg "Cannot find path '$tFile' in workspace, If you want to include files that not in your app directory, please use 'appIncludedFiles'."
                        New-Message $ErrorMsg "EditableFileNotFound" "Cannot find path '$tFile' in workspace, If you want to include files that not in your app directory, please use 'appIncludedFiles'."
                    } else {
                        New-Message $InfoMsg "Copy file: $sFile -----> $tFile."
                        Copy-Item -Path $sFile -Destination $tFile -Force | Out-Null
                    }
                }
            }
        }
    } else {
        New-Message $InfoMsg "Site '$siteName' is not a valid or path '$($site.physicalPath)' does not exist. Continuing extraction ..."
    }
    #Copy web apps
    foreach($webAppName in $($inputTable.includedWebApps)) {
        $webApp = Get-WebApplication -Name $webAppName
        if (($webApp) -and (Test-Path $webApp.physicalPath)) {
            $webAppLeaf = Split-Path -Path $webApp.physicalPath -Leaf
            $webAppPath = "$editableFilePath\$webAppLeaf"
            if (Test-Path $webAppPath) {
                $files = Get-ChildItem -Path $webAppPath -Recurse
                foreach($file in $files) {
                    if (-not $file.PSIsContainer) {
                        $sfName =  $file.Name.toString()
                        $sfDir = $file.Directory.toString()
                        $sFile = $sfDir + "\" + $sfName
                        $tFile = $sFile -replace 'EditableFiles','Artifacts'
                        if ($mainAppId) {
                            $tFile = $tFile -replace $appId,$mainAppId
                        }
                        if (!(Test-Path $tFile)) {
                            New-Message $InfoMsg "Cannot find path '$tFile' in workspace, If you want to include files that not in your app directory, please use 'appIncludedFiles'."
                            New-Message $InfoMsg "EditableFileNotFound"
                        } else {
                            New-Message $InfoMsg "Copy file: $sFile -----> $tFile."
                            Copy-Item -Path $sFile -Destination $tFile -Force | Out-Null
                        }
                    }
                }
            }
        } else {
            New-Message $InfoMsg "App '$webAppName' is not a valid web application or path '$($webApp.physicalPath)' does not exist. Double check your included apps field is correct. Continuing extraction ..."
        }
    }
}

function Copy-IncludedFiles {
    if ($inputTable.appIncludedFiles) {
        $includedFilePath = $script:artifactPath + "includedFiles\"
        try {
            Create-Dir -path $includedFilePath -cleanDir $true
        } catch {
            New-Message $ErrorMsg "CreateInclDirFail" $_.Exception.Message
        }

        foreach ($file in $inputTable.appIncludedFiles) {
            $sfName =  split-Path -Path $file -Leaf
            $sfDir = split-Path -Path $file -Parent
            $sFile = $sfDir + "\" + $sfName
            #Can only handle files on C drive as base image only has C drive.
            if ((Test-Path $sFile) -and ((Get-Item $sFile).PSDrive.Name -eq "C")) {
                $tFile = $includedFilePath + $sfName
                Copy-Item -Path $sFile -Destination $tFile -Force | Out-Null
            } else {
                New-Message $InfoMsg "Included file: '$sFile' cannot be found or not on C drive."
                New-Message $ErrorMsg "InclFileNotFound"
            }
        }
    }
}

function Copy-AdditionalApps {
    if ($inputTable.additionalApps -AND (-Not $mainAppId)) {
        foreach ($additionalAppId in $inputTable.additionalApps) {
            # Read analysis.json and appType of additional app
            $analysisPath = $workspacePath + "\" + $additionalAppId + "\" + "analysis.json"
            if(!(Test-Path $analysisPath)) {
                New-Message $ErrorMsg "AnalysisNotRun" "analysis.json file not found for '$additionalAppId'"
                Exit-Application
            }
            try {
                $analysisFile = Get-Content $analysisPath | Out-String | ConvertFrom-Json
            } catch {
                New-Message $ErrorMsg "JsonValidationFailed" $_.Exception.Message
                Exit-Application
            }
            $analysisInfo = $analysisFile.analysisInfo
            if (-Not $analysisInfo) {
                New-Message $ErrorMsg "InvalidJsonFormat" "analysisInfo not found in analysis.json file"
                Exit-Application
            }
            $appType = $analysisInfo.appType
            if (-Not $appType) {
                New-Message $ErrorMsg "InvalidJsonFormat" "analysisInfo.appType not found in analysis.json file"
                Exit-Application
            }
            if ($appType -ne [AppType]::IIS -AND $appType -ne [AppType]::Service) {
                New-Message $ErrorMsg "InvalidAppType" "We only support IIS or Service as appType"
                Exit-Application
            }

            # Branch on application type: IIS or Service
            if ($appType -eq [AppType]::IIS) {
                # For IIS Sites, we recursively call the same extract.ps1 script with an additional argument mainAppId.
                $extractPSPath = $PSScriptRoot + "\extract.ps1"
                $Command = $extractPSPath + " -inputScript " + $analysisPath + " -workspacePath " + $workspacePath + " -appId " + $additionalAppId + " -mainAppId " + $appId + " -appType IIS"
                Invoke-Expression $Command
            } elseif ($appType -eq [AppType]::Service) {
                Copy-WindowsService $analysisInfo.serviceName $analysisInfo.serviceBinary $analysisInfo.serviceDir
            }
        }
    }
}

function Copy-WindowsService([string] $serviceName, [string] $serviceBinary, [string] $serviceDir) {
    if (!$serviceBinary -or !$serviceBinary -or !$serviceBinary) {
        New-Message $ErrorMsg "InvalidAppInfo" "Please provide ServiceName, ServiceBinary and ServiceDir"
        Exit-Application
    }
    $service = cmd /c sc qc $serviceName | findstr BINARY
    if ($service) {
        # Skip file copy for Windows native service
        if ($serviceDir -like '*System32*') {
            New-Message $InfoMsg "Skipping artifact copy for $serviceName since it looks like a system32 service which should already exist in the container base image"
            continue
        }
        if (Test-Path $serviceDir) {
            $dstPath = $script:artifactPath + "\" + $serviceName
            try {
                Create-Dir -path $dstPath -cleanDir $true
                CopyDir $serviceDir $dstPath
            } catch {
                New-Message $ErrorMsg "Failed to create/copy into dir: '$dstPath'. $_.Exception.Message"
            }
        } else {
            New-Message $ErrorMsg "For Service $service, could not find service path $serviceDir., skipping..."
        }
    } else {
        New-Message $InfoMsg "Cannot find service: '$serviceName', skipping..."
    }
}

function Generate-Archive {
    New-Message $InfoMsg "Generating archive file for artifacts..."
    $artifactFolder = split-Path -Path $artifactPath -Parent
    $key = "$appId/$appId.zip"
    $zipFile = $artifactFolder + "\" + $appId + ".zip"
    If(Test-path $zipFile) {
        Remove-item $zipFile -Force
    }
    $appDirectory = $workspacePath + "\" + $appId
    $analysisPath = $appDirectory + "\" + "analysis.json"
    $reportPath = $appDirectory + "\" + "report.txt"

    # Compressing into zip using .NET instead of powershell for memory optimization
    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($artifactPath, $zipFile, $compressionLevel, $true)

    # Opening zip to add analysis and report files to the zip
    $zip = [System.IO.Compression.ZipFile]::Open($zipFile, 'update')
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $analysisPath, (Split-Path $analysisPath -Leaf), $compressionLevel)
    if (Test-path $reportPath) {
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $reportPath, (Split-Path $reportPath -Leaf), $compressionLevel)
    }
    $zip.Dispose()

    New-Message $InfoMsg "Archive file generated. '$zipFile'."
    if ($uploadToS3) {
        if ($profileName) {
            $bucketExist = Get-S3Bucket -BucketName $s3BucketName -ProfileName $profileName
        } else {
            $bucketExist = Get-S3Bucket -BucketName $s3BucketName
        }
        $bucketExist = Get-S3Bucket -BucketName $s3BucketName -ProfileName $profileName
        if ($bucketExist) {
            $Params = @{
                BucketName = "$s3BucketName";
                Key = $key;
                File = "$zipFile";
            }
            try {
                New-Message $InfoMsg "Uploading archive file..."
                if ($profileName) {
                    Write-S3Object @Params -Confirm:$false -Force -ProfileName $profileName
                } else {
                    Write-S3Object @Params -Confirm:$false -Force
                }
                New-Message $InfoMsg "Archive file '$key' uploaded to bucket '$s3BucketName'."
                New-Message $InfoMsg "Archive file available at s3://$s3BucketName/$key"
            } catch {
                New-Message $InfoMsg "Failed to upload archive file to S3, continue..."
            }
        } else {
            New-Message $InfoMsg "S3 bucket $s3BucketName doesn't exit, skip archive upload."
        }
    }
}

try {
    $LASTEXITCODE = $null
    New-Message $InfoMsg "Start Extract for application: '$appId'."
    Check-Prerequisites
    Prepare-Inputs
    Copy-Artifact
    Update-Artifact
    if (-Not $mainAppId) {
        Generate-Archive
    }
    New-Message $InfoMsg "Extract for application: '$appId' completed."
} catch {
    New-Message $InfoMsg "Internal error occurred. $_.Exception.Message"
    New-Message $ErrorMsg "PSUnknownException" $_.Exception.Message
    Exit-Application
}