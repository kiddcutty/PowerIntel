# Developed by Russell Overton & Jesse Cutshall
#
#
param(
    [string]$JsonPath,
    [string]$CsvPath
)

# Helper: determine if running on Windows
$IsWindowsPlatform = $false
try {
    if (Get-Variable -Name IsWindows -Scope 0 -ErrorAction SilentlyContinue) {
        $IsWindowsPlatform = $IsWindows
    } else {
        $IsWindowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
    }
} catch {
    try {
        $plat = [System.Environment]::OSVersion.Platform
        $IsWindowsPlatform = ($plat -eq [System.PlatformID]::Win32NT)
    } catch {
        $IsWindowsPlatform = $false
    }
}

function Get-FilePathFromConsole {
    param(
        [string]$Prompt
    )
    while ($true) {
        $p = Read-Host $Prompt
        if ([string]::IsNullOrWhiteSpace($p)) {
            Write-Host "No path entered. Exiting script." -ForegroundColor Red
            exit 1
        }
        if (Test-Path $p) { return (Resolve-Path $p).Path }
        Write-Host "File not found at '$p'. Try again or Ctrl+C to cancel." -ForegroundColor Yellow
    }
}

function Show-OpenFileDialog {
    param(
        [string]$InitialDir = (Get-Location).Path,
        [string]$Filter = "All files (*.*)|*.*",
        [string]$Title = "Select a file"
    )

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop

        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.InitialDirectory = $InitialDir
        $ofd.Filter = $Filter
        $ofd.Title = $Title
        $ofd.Multiselect = $false

        $result = $ofd.ShowDialog()
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            return $ofd.FileName
        } else {
            return $null
        }
    } catch {
        # GUI unavailable (headless or assembly missing)
        return $null
    }
}

# ---------------------------
# 1) Choose enterprise-attack.json
# ---------------------------
if ($JsonPath) {
    if (-not (Test-Path $JsonPath)) {
        Write-Host "Provided JsonPath '$JsonPath' does not exist. Exiting." -ForegroundColor Red
        exit 1
    }
    $jsonPath = (Resolve-Path $JsonPath).Path
} else {
    if ($IsWindowsPlatform) {
        $jsonPath = Show-OpenFileDialog -Filter "JSON files (*.json)|*.json|All files (*.*)|*.*" -Title "Select enterprise-attack.json file"
        if (-not $jsonPath) {
            Write-Host "Windows file dialog not used or cancelled. Falling back to console input..."
            $jsonPath = Get-FilePathFromConsole -Prompt "Enter the full path to enterprise-attack.json"
        }
    } else {
        $jsonPath = Get-FilePathFromConsole -Prompt "Enter the full path to enterprise-attack.json"
    }
}

Write-Host "Selected file: $jsonPath" -ForegroundColor Green
$file = Get-Content -Path $jsonPath

#Turn it from JSON into a standard powershell array
$obj1 = $file | ConvertFrom-Json

#It stuffs everything under a bundle - this next bit pulls out the ojects into a standard collection.
$obj2 = $obj1.objects

#make an empty list to hold the APT groups we'll eventually derive.
$results = New-Object System.Collections.Generic.List[System.Object]
$results2 = New-Object System.Collections.Generic.List[System.Object]

# ---------------------------
# 2) Choose techniques.csv
# ---------------------------
if ($CsvPath) {
    if (-not (Test-Path $CsvPath)) {
        Write-Host "Provided CsvPath '$CsvPath' does not exist. Exiting." -ForegroundColor Red
        exit 1
    }
    $csvPath = (Resolve-Path $CsvPath).Path
} else {
    if ($IsWindowsPlatform) {
        $csvPath = Show-OpenFileDialog -Filter "CSV files (*.csv)|*.csv|All files (*.*)|*.*" -Title "Select techniques.csv file"
        if (-not $csvPath) {
            Write-Host "Windows file dialog not used or cancelled. Falling back to console input..."
            $csvPath = Get-FilePathFromConsole -Prompt "Enter the full path to techniques.csv"
        }
    } else {
        $csvPath = Get-FilePathFromConsole -Prompt "Enter the full path to techniques.csv"
    }
}

Write-Host "Selected file: $csvPath" -ForegroundColor Green
$list = Import-Csv -Path $csvPath

### Function for creating the MITRE Attack Navigator Layer from 
### list of Technique IDs and Tactics ($techInfo) then outputing JSON file 
function New-NavLayer {
    param(
        [Parameter(Mandatory)]
        [string]$aptGroupName,
        [Parameter(Mandatory)]
        [string]$aptNumber,
        [Parameter(Mandatory)]
        [hashtable]$aptTable
    )

    $jsonLayer = [ordered]@{
        name                          = "$aptGroupName"
        versions                      = @{}
        domain                        = "enterprise-attack"
        description                   = ""
        filters                       = @{}
        sorting                       = "0"
        layout                        = @{}
        hideDisabled                  = "true"
        techniques                    = @()
        gradient                      = @{}
        legendItems                   = @()
        metadata                      = ""
        links                         = ""
        showTacticRowBackground       = "false"
        TacticRowBackground           = "#dddddd"
        selectTechniquesAcrossTactics = "true"
        selectSubtechniquesWithParent = "false"
        selectVisibleTechniques       = "false"
    }

    $jsonLayer.versions = @{
        attack    = "17"
        navigator = "5.1.0"
        layer     = "4.5"
    }
    $jsonLayer.filters = @{
        platforms = @("Linux", "macOS", "Windows", "PRE", "Containers", "Network", "Office 365", "SaaS", "Google Workspace", "IaaS", "Azure AD")
    }
    $jsonLayer.layout = @{
        layout               = "side"
        aggregateFunction    = "max"
        showID               = "true"
        showName             = "true"
        showAggregatedScores = "true"
        countUnscored        = "false"
    }
    $jsonLayer.gradient = @{
        colors   = @("#8ec843ff", "#ffe766ff", "#ff6666ff")
        minValue = 0
        maxValue = $aptNumber
    }
    $jsonLayer.legendItems = @(
        @{
            label = "Least Likely"
            color = "#8ec843ff"
        },
        @{
            label = "Most Likely"
            color = "#ff6666ff"
        }
    )

    foreach ($tactic in $aptTable[$aptGroupName].Keys) {
        foreach ($techID in $aptTable[$aptGroupName][$tactic]) {
            $newTechnique = [ordered]@{
                techniqueID       = $techID
                tactic            = $tactic
                score             = 1
                color             = ""
                comment           = ""
                enabled           = "true"
                metadata          = ""
                links             = ""
                showSubtechniques = "true"
            }
            $jsonLayer.techniques += $newTechnique
        }
    }

    $jsonLayer = $jsonLayer | ConvertTo-Json -Depth 5
    $jsonLayer | Out-File ".\$aptGroupName.json"
}

#this whole thing gets wrapped in a foreach loop
##BEGIN MASTER LOOP
$attack_list = $obj2 | Where-Object type -eq "attack-pattern"
$rel_list = $obj2 | Where-Object { $_.type -eq "relationship" -and $_.relationship_type -eq "uses" -and $_.source_ref -like "intrusion*" }
$intrusion_list = $obj2 | Where-Object { $_.type -eq "intrusion-set" }

foreach ($techid in $list) {
    $tech = $techid.TechniqueID

    Write-Host "==============================================================" -ForegroundColor Yellow
    Write-Host "$tech is associated with attack patterns:" -ForegroundColor Yellow

    ForEach ($attack in $attack_list) {

        $attackid = ($attack.external_references).external_id

        if ($attackid -eq $tech) {
            $pattern = $attack.id
            Write-Output "$pattern"
            "`n"
            Write-Host ". . . which is associated with this intrusion set . . ." -ForegroundColor DarkYellow

            $test_pattern = $rel_list | Where-Object { $_.target_ref -eq $pattern -and $_.source_ref -like "intrusion*" }
            $test_pattern.source_ref
            "`n"

            Write-Host "aliased to:" -ForegroundColor DarkYellow
            foreach ($pattern in $test_pattern) {
                $group = $intrusion_list | Where-Object { $_.id -eq $pattern.source_ref }
                $group.name
                $results.Add($group.name)
            }
        }
    }
    "`n"
}

$aptNum = Read-Host "Enter number of groups"
"`n"
"`n"
"`n"
Write-Host "--------------------------------------------------------" -ForegroundColor DarkYellow
Write-Host "Total Final List (duplicative) of All Groups Implicated" -ForegroundColor DarkYellow
Write-Host "--------------------------------------------------------" -ForegroundColor DarkYellow

$results | Group-Object -NoElement | Sort-Object -Property count -Descending | Select-Object -First $aptNum
Start-Sleep -Seconds 3
"`n"
Write-Host "compiling list for selected groups . . ." -ForegroundColor DarkYellow
$apt_list = $results | Group-Object -NoElement | Sort-Object -Property count -Descending | Select-Object -First $aptNum
Write-Host "===============" -ForegroundColor DarkYellow
$apt_list.name
Write-Host "===============" -ForegroundColor DarkYellow
Start-Sleep -Seconds 5
"`n"
foreach ($apt in $apt_list) {
    $entry = $intrusion_list | Where-Object { $_.name -eq $apt.name } | Select-Object -First 1 -Property id
    $results2.Add($entry)
}

$aptTable = @{}

$len = $results2.Count
$i = 0
while ($i -lt $len) {
    $aptGroup = $apt_list[$i].name
    Write-Host "===============" -ForegroundColor DarkYellow
    $aptGroup
    Write-Host "===============" -ForegroundColor DarkYellow
    Write-Host "corresponds to intrusion_set: " -ForegroundColor DarkYellow $results2[$i]
    Write-Host "containing the following techniques . . ." -ForegroundColor DarkYellow
    $out = $rel_list | Where-Object { $_.source_ref -eq $results2[$i].id -and $_.target_ref -like "attack*" } | Select-Object target_ref
    $targetList = $out.target_ref
    Write-Output $targetList
    "`n"

    foreach ($item in $targetList) {
        $matchedAttacks = $attack_list | Where-Object { $_.id -eq $item }
        foreach ($attck in $matchedAttacks) {
            $techniqueRef = $attck.external_references | Where-Object { $_.source_name -eq "mitre-attack" }
            $techID = $techniqueRef.external_id
            $tactics = $attck.kill_chain_phases | ForEach-Object { $_.phase_name }

            foreach ($tactic in $tactics) {
                if (-not $aptTable.ContainsKey($aptGroup)) {
                    $aptTable[$aptGroup] = @{}
                }

                if (-not $aptTable[$aptGroup].ContainsKey($tactic)) {
                    $aptTable[$aptGroup][$tactic] = @()
                }

                if (-not $aptTable[$aptGroup][$tactic].Contains($techID)) {
                    $aptTable[$aptGroup][$tactic] += $techID
                }
            }
        }
    }

    Write-Host "===============================================" -ForegroundColor DarkYellow
    Write-Host "Building Navigator Layer for $aptGroup" -ForegroundColor DarkYellow
    Write-Host "===============================================" -ForegroundColor DarkYellow
    Start-Sleep -Seconds 3
    "`r"
    New-NavLayer -aptGroupName $aptGroup -aptNumber $aptNum -aptTable $aptTable
    $i++
    "`n"
}

Write-Host "=== APT Groups with Tactics and Techniques ===" -ForegroundColor Green

foreach ($aptGroup in $aptTable.Keys) {
    Write-Host "`nAPT Group: $aptGroup" -ForegroundColor DarkYellow
    Write-Host "==========================================================" -ForegroundColor DarkYellow

    foreach ($tactic in $aptTable[$aptGroup].Keys) {
        Write-Host " Tactic: $tactic" -ForegroundColor Magenta
        foreach ($techID in $aptTable[$aptGroup][$tactic]) {
            Write-Host "   - $techID" -ForegroundColor White
        }
    }
}
