$psVersion = $PSVersionTable.PSVersion.Major
if ($psVersion -lt 5) {
    Exit
}

Register-ArgumentCompleter -Native -CommandName 'app2container' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $a2cConfFile = Join-Path -Path $env:LOCALAPPDATA -ChildPath ".app2container-config\app2container.conf"
    $inventoryFile = Join-Path -Path $env:LOCALAPPDATA -ChildPath ".app2container-config\inventory.json"
    $remoteTargetFile = Join-Path -Path $env:LOCALAPPDATA -ChildPath ".app2container-config\remote_hosts.conf"
    $remoteInventoryFile = @(
        $a2cConf = Get-Content $a2cConfFile | Out-String | ConvertFrom-Json
        $remoteInventoryPath = "\remote\" + $commandAst.CommandElements[4].Value + "\inventory.json"
        Join-Path -Path $a2cConf.workspace -ChildPath $remoteInventoryPath
    )

    $commandElements = $commandAst.CommandElements
    $charLen = $($commandElements -join ' ').Length
    $command = @(
    'app2container'
    for ($i = 1; $i -lt $commandElements.Count; $i++) {
        $element = $commandElements[$i]
        if ($element -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -or
                $element.StringConstantType -ne [System.Management.Automation.Language.StringConstantType]::BareWord -or
                ($i -eq $commandElements.Count - 1 -and $cursorPosition -eq $charLen))
        {
            break
        }
        $element.Value
    }
    ) -join ';'
    $completions = @(switch -wildcard ($command)
    {
        'app2container;*--target;*--application-id' {
            if (Test-Path $remoteInventoryFile -PathType Leaf) {
                $inventory = Get-Content $remoteInventoryFile | Out-String | ConvertFrom-Json
                foreach ($i in $inventory.psobject.properties) {
                    [System.Management.Automation.CompletionResult]::new($i.name)
                }
            }
            break
        }
        'app2container;*--application-id' {
            if (Test-Path $inventoryFile -PathType Leaf) {
                $inventory = Get-Content $inventoryFile | Out-String | ConvertFrom-Json
                foreach ($i in $inventory.psobject.properties) {
                    [System.Management.Automation.CompletionResult]::new($i.name)
                }
            }
            break
        }
        'app2container;*--target' {
            if (Test-Path $remoteTargetFile -PathType Leaf) {
                $inventory = Get-Content $remoteTargetFile | Out-String | ConvertFrom-Json
                foreach ($i in $inventory.psobject.properties) {
                    [System.Management.Automation.CompletionResult]::new($i.name)
                }
            }
            break
        }
        'app2container' {
            [System.Management.Automation.CompletionResult]::new('init ')
            [System.Management.Automation.CompletionResult]::new('inventory ')
            [System.Management.Automation.CompletionResult]::new('analyze ')
            [System.Management.Automation.CompletionResult]::new('extract ')
            [System.Management.Automation.CompletionResult]::new('containerize ')
            [System.Management.Automation.CompletionResult]::new('generate ')
            [System.Management.Automation.CompletionResult]::new('remote ')
            [System.Management.Automation.CompletionResult]::new('upgrade ')
            [System.Management.Automation.CompletionResult]::new('upload-support-bundle ')
            [System.Management.Automation.CompletionResult]::new('help')
            break
        }
        'app2container;init' {
            [System.Management.Automation.CompletionResult]::new('--advanced ')
            break
        }
        'app2container;inventory' {
            [System.Management.Automation.CompletionResult]::new('--type ')
            [System.Management.Automation.CompletionResult]::new('--nofilter ')
            break
        }
        'app2container;*--type' {
            [System.Management.Automation.CompletionResult]::new('iis ')
            [System.Management.Automation.CompletionResult]::new('service ')
            break
        }
        'app2container;analyze' {
            [System.Management.Automation.CompletionResult]::new('--application-id ')
            break
        }
        'app2container;extract' {
            [System.Management.Automation.CompletionResult]::new('--application-id ')
            [System.Management.Automation.CompletionResult]::new('--output ')
            break
        }
        'app2container;containerize' {
            [System.Management.Automation.CompletionResult]::new('--application-id ')
            [System.Management.Automation.CompletionResult]::new('--input-archive ')
            [System.Management.Automation.CompletionResult]::new('--build-only ')
            [System.Management.Automation.CompletionResult]::new('--force ')
            break
        }
        'app2container;generate' {
            [System.Management.Automation.CompletionResult]::new('app-deployment ')
            [System.Management.Automation.CompletionResult]::new('pipeline ')
            break
        }
        'app2container;generate;app-deployment' {
            [System.Management.Automation.CompletionResult]::new('--application-id ')
            [System.Management.Automation.CompletionResult]::new('--deploy ')
            break
        }
        'app2container;generate;pipeline' {
            [System.Management.Automation.CompletionResult]::new('--application-id ')
            [System.Management.Automation.CompletionResult]::new('--deploy ')
            break
        }
        'app2container;remote' {
            [System.Management.Automation.CompletionResult]::new('configure ')
            [System.Management.Automation.CompletionResult]::new('inventory ')
            [System.Management.Automation.CompletionResult]::new('analyze ')
            [System.Management.Automation.CompletionResult]::new('extract ')
            break
        }
        'app2container;remote;configure' {
            [System.Management.Automation.CompletionResult]::new('--input-json ')
            break
        }
        'app2container;remote;inventory' {
            [System.Management.Automation.CompletionResult]::new('--target ')
            [System.Management.Automation.CompletionResult]::new('--type ')
            [System.Management.Automation.CompletionResult]::new('--nofilter ')
            break
        }
        'app2container;remote;analyze' {
            [System.Management.Automation.CompletionResult]::new('--target ')
            [System.Management.Automation.CompletionResult]::new('--application-id ')
            break
        }
        'app2container;remote;analyze;--target;*' {
            [System.Management.Automation.CompletionResult]::new('--application-id ')
            break
        }
        'app2container;remote;extract' {
            [System.Management.Automation.CompletionResult]::new('--target ')
            [System.Management.Automation.CompletionResult]::new('--application-id ')
            [System.Management.Automation.CompletionResult]::new('--output ')
            break
        }
        'app2container;remote;extract;--target;*;--application-id;*' {
            [System.Management.Automation.CompletionResult]::new('--output ')
            break
        }
        'app2container;remote;extract;--target;*' {
            [System.Management.Automation.CompletionResult]::new('--application-id ')
            [System.Management.Automation.CompletionResult]::new('--output ')
            break
        }
        'app2container;upgrade' {
            [System.Management.Automation.CompletionResult]::new('--custom-patch ')
            break
        }
        'app2container;upload-support-bundle' {
            [System.Management.Automation.CompletionResult]::new('--application-id ')
            [System.Management.Automation.CompletionResult]::new('--support-message ')
            break
        }
        'app2container;help' {
            break
        }
    })
    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
            Sort-Object -Property ListItemText
}
# Uncomment along with lines in install.ps for suggestion autocomplete features rather than toggle
#Set-PSReadlineKeyHandler -Key Tab -Function Complete
