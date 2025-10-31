#Open dialog box for user to select enterprise-attack.json file location
[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.InitialDirectory = Get-Location  # Sets to current directory, or you can specify a path
$OpenFileDialog.filter = "All files (*.*) | *.*"
$OpenFileDialog.Title = "Select enterprise-attack.json file"
$dialogResult = $OpenFileDialog.ShowDialog()

if ($dialogResult -eq "OK") {
    $jsonPath = $OpenFileDialog.FileName
    Write-Host "Selected file: $jsonPath" -ForegroundColor Green
    $file = Get-Content -Path $jsonPath
} else {
    Write-Host "No file selected. Exiting script." -ForegroundColor Red
    exit
}
#$file = get-content .\enterprise-attack.json  

#Turn it from JSON into a standard powershell array
$obj1 = $file | convertfrom-json

#It stuffs everything under a bundle - this next bit pulls out the ojects into a standard collection.
$obj2 = $obj1.objects

#make an empty list to hold the APT groups we'll eventually derive.
$results = New-Object System.Collections.Generic.List[System.Object]
$results2 = New-Object System.Collections.Generic.List[System.Object]

#Open dialog box for user to select techniques.csv file location
[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.InitialDirectory = Get-Location  # Sets to current directory, or you can specify a path
$OpenFileDialog.filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
$OpenFileDialog.Title = "Select techniques.csv file"
$dialogResult = $OpenFileDialog.ShowDialog()

if ($dialogResult -eq "OK") {
    $csvPath = $OpenFileDialog.FileName
    Write-Host "Selected file: $csvPath" -ForegroundColor Green
    $list = import-csv -Path $csvPath
} else {
    Write-Host "No file selected. Exiting script." -ForegroundColor Red
    exit
}
#$list = import-csv -Path "./techniques.csv"

### Function for creating the MITRE Attack Navigator Layer from 
### list of Technique IDs and Tactics ($techInfo) then outputing JSON file 
## Build MITRE Attack Navigator Layer Template ##
## Gradient is set for Green (low score) to Red (high score). 
## The legend is built to reflect Least to Most Likely 
## Set gradient max value to number of APTs 
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
        versions                      = @{
            attack    = "17"
            navigator = "5.1.0"
            layer     = "4.5"
        }
        domain                        = "enterprise-attack"
        description                   = ""
        filters                       = @{
            platforms = @("Linux", "macOS", "Windows", "PRE", "Containers", "Network", "Office 365", "SaaS", "Google Workspace", "IaaS", "Azure AD")
        }
        sorting                       = "0"
        layout                        = @{
            layout               = "side"
            aggregateFunction    = "max"
            showID               = "true"
            showName             = "true"
            showAggregatedScores = "true"
            countUnscored        = "false"
        }
        hideDisabled                  = "true"
        techniques                    = @()
        gradient                      = @{
            colors   = @("#8ec843ff", "#ffe766ff", "#ff6666ff")
            minValue = 0
            maxValue = $aptNumber
        }
        legendItems                   = @(
            @{
                label = "Least Likely"
                color = "#8ec843ff"
            },
            @{
                label = "Most Likely"
                color = "#ff6666ff"
            })
        metadata                      = ""
        links                         = ""
        showTacticRowBackground       = "false"
        TacticRowBackground           = "#dddddd"
        selectTechniquesAcrossTactics = "true"
        selectSubtechniquesWithParent = "false"
        selectVisibleTechniques       = "false"
    }

    ## Build each Technique in Attack Navigator JSON based on TechID and Tactic ##
    ## For techniques with multiple tactics a technique will be built for each tactic ##
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

    ## Convert to JSON and output file for MITRE Attack Navigator ##
    $jsonLayer = $jsonLayer | ConvertTo-Json -Depth 5
    $jsonLayer | Out-File ".\$aptGroupName.json"
}

#this whole thing gets wrapped in a foreach loop
##BEGIN MASTER LOOP
#attack_list contains every stanza that identifies an attack pattern.  
$attack_list = $obj2 | where-object type -eq "attack-pattern"
#rel_list stores all the relationship stanzas where an intrusion set is listed as using something like an attack pattern or tool
$rel_list = $obj2 | Where-Object { $_.type -eq "relationship" -and $_.relationship_type -eq "uses" -and $_.source_ref -like "intrusion*" }
#intrusion_list is literally every stanza with a type of "intrusion_set".  Too broad, but oh well 
$intrusion_list = $obj2 | Where-Object { $_.type -eq "intrusion-set" }

#This foreach is taking the lines from the CSV and pulling in the technique names for evaluation
foreach ($techid in $list) {
    #i made this variable to avoid typing $techid.TechniqueID over and over again
    $tech = $techid.TechniqueID
    
    Write-Host "==============================================================" -ForegroundColor Yellow
    Write-Host "$tech is associated with attack patterns:" -ForegroundColor Yellow
    


    #this foreach is pulling technique ids out of all the attack-pattern stanzas in the attack_list
    #it then checks to see if one of them matches the current technique id we're looking at for the iteration
    #if it does, we set the "pattern" variable equal to the attach-pattern id
    #-------techique ids are similar to "T1609" while attack pattern ids look more like "attack-pattern--6ee2dc99-91ad-4534-a7d8-a649358c331f"
    #we write out the matched attack pattern id to the screen (should be one per tech id)

    ForEach ($attack in $attack_list) {

        $attackid = ($attack.external_references).external_id


        if ($attackid -eq $tech) {
            $pattern = $attack.id
            Write-Output "$pattern"
            "`n"
            Write-Host ". . . which is associated with this intrusion set . . ." -ForegroundColor DarkYellow

            #here we're taking the attack-pattern id and finding all the intrusion sets that include it.  Then we store that list in the test_pattern variable    
            $test_pattern = $rel_list | Where-Object { $_.target_ref -eq $pattern -and $_.source_ref -like "intrusion*" }
            $test_pattern.source_ref
            "`n"

            #this chunk here is going to try to match the intrusion set ids to the generic group names for APTs
            Write-Host "aliased to:" -ForegroundColor DarkYellow
            foreach ($pattern in $test_pattern) {
                $group = $intrusion_list | Where-Object { $_.id -eq $pattern.source_ref }
                #we end up with a set of objects, but we really only want one property - the name.
                $group.name
                #now we take that list list of names and append it to the list we created at the top.
                $results.Add($group.name)
                
            }
        }
    }
    "`n" 
} #end master

#now we're just listing out all the APTs we found to use our techniques.  we group them up and count how many times they were implicated.  
#sort that list and pull out the top three


$aptNum = Read-Host "Enter number of groups"
"`n"
"`n"
"`n"
Write-Host "--------------------------------------------------------" -ForegroundColor DarkYellow
Write-Host "Total Final List (duplicative) of All Groups Implicated" -ForegroundColor DarkYellow
Write-Host "--------------------------------------------------------" -ForegroundColor DarkYellow 

$results | Group-Object -NoElement | Sort-Object -Property count -Descending | Select-Object -first $aptNum
Start-Sleep -Seconds 3
"`n"
write-host "compiling list for selected groups . . ." -ForegroundColor DarkYellow
$apt_list = $results | Group-Object -NoElement | Sort-Object -Property count -Descending | Select-Object -first $aptNum
Write-Host "===============" -ForegroundColor DarkYellow
$apt_list.name
Write-Host "===============" -ForegroundColor DarkYellow
Start-Sleep -Seconds 5
"`n"
foreach ($apt in $apt_list) {
    $entry = $entry = $intrusion_list | Where-Object { $_.name -eq $apt.name } | Select-Object id
    
    $results2.add($entry)
    
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
    # Write-Output "Iteration: $i"
    # Write-Output "APT Group: $aptGroup"
    # Write-Output "Intrusion Set ID: $($results2[$i])"

    #Build hashtable with structure [APTNAME][TACTICS][TECHID]

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





