<#
.SYNOPSIS
    STIG Analysis Desktop Application with MS Access Database

.DESCRIPTION
    Professional desktop application for analyzing STIG files with persistent data storage.
    View, search, and analyze STIG data directly in a modern GUI interface.

.NOTES
    Requirements: Windows 10, PowerShell 5.1+, Microsoft Access Database Engine 2016
    Version: 2.0 - Desktop Application Edition
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

# Add required assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Data

# Script configuration
$ErrorActionPreference = 'Stop'
$script:DatabasePath = Join-Path $PSScriptRoot "STIGAnalysis.accdb"
$script:DatabaseConnection = $null
$script:MainForm = $null

#region Database Connection Class

class DatabaseConnection {
    [string]$ConnectionString
    [System.Data.OleDb.OleDbConnection]$Connection
    [bool]$IsConnected = $false

    DatabaseConnection([string]$DatabasePath) {
        $this.ConnectionString = "Provider=Microsoft.ACE.OLEDB.16.0;Data Source=$DatabasePath;Persist Security Info=False;"
        $this.Connection = New-Object System.Data.OleDb.OleDbConnection($this.ConnectionString)
    }

    [bool] Connect() {
        try {
            if ($this.Connection.State -ne 'Open') {
                $this.Connection.Open()
            }
            $this.IsConnected = $true
            return $true
        }
        catch {
            Write-Error "Failed to connect to database: $($_.Exception.Message)"
            $this.IsConnected = $false
            return $false
        }
    }

    [void] Disconnect() {
        try {
            if ($this.Connection.State -eq 'Open') {
                $this.Connection.Close()
            }
        }
        catch {
            Write-Warning "Error closing database connection: $($_.Exception.Message)"
        }
        finally {
            $this.IsConnected = $false
        }
    }

    [System.Data.DataTable] ExecuteQuery([string]$Query) {
        $dataTable = New-Object System.Data.DataTable
        try {
            $command = $this.Connection.CreateCommand()
            $command.CommandText = $Query
            $adapter = New-Object System.Data.OleDb.OleDbDataAdapter($command)
            $adapter.Fill($dataTable) | Out-Null
        }
        catch {
            throw "Query failed: $($_.Exception.Message)"
        }
        return $dataTable
    }

    [int] ExecuteNonQuery([string]$Query) {
        try {
            $command = $this.Connection.CreateCommand()
            $command.CommandText = $Query
            return $command.ExecuteNonQuery()
        }
        catch {
            throw "Query failed: $($_.Exception.Message)"
        }
    }
}

#endregion

#region Database Initialization

function Initialize-Database {
    param([string]$DbPath)
    
    if (Test-Path $DbPath) {
        Write-Host "Database found: $DbPath" -ForegroundColor Green
        return $true
    }
    
    Write-Host "Creating new database..." -ForegroundColor Cyan
    
    try {
        # Create database
        $catalog = New-Object -ComObject ADOX.Catalog
        $catalog.Create("Provider=Microsoft.ACE.OLEDB.16.0;Data Source=$DbPath")
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($catalog) | Out-Null
        
        # Create tables
        $conn = [DatabaseConnection]::new($DbPath)
        $conn.Connect()
        
        # Sites table
        $conn.ExecuteNonQuery(@"
CREATE TABLE Sites (
    Site_ID AUTOINCREMENT PRIMARY KEY,
    Site_Name VARCHAR(255) NOT NULL,
    Description TEXT,
    Location VARCHAR(255),
    Created_Date DATETIME
)
"@) | Out-Null
        
        # Systems table
        $conn.ExecuteNonQuery(@"
CREATE TABLE Systems (
    System_ID AUTOINCREMENT PRIMARY KEY,
    Site_ID INTEGER NOT NULL,
    System_Name VARCHAR(255) NOT NULL,
    Description TEXT,
    IP_Address VARCHAR(50),
    Hostname VARCHAR(255),
    Created_Date DATETIME
)
"@) | Out-Null
        
        # CCI Mappings table
        $conn.ExecuteNonQuery(@"
CREATE TABLE CCI_Mappings (
    CCI_ID VARCHAR(20) PRIMARY KEY,
    NIST_Controls TEXT,
    Control_Families TEXT,
    Description TEXT,
    Import_Date DATETIME,
    Source_File VARCHAR(255)
)
"@) | Out-Null
        
        # STIG Files table
        $conn.ExecuteNonQuery(@"
CREATE TABLE STIG_Files (
    File_ID AUTOINCREMENT PRIMARY KEY,
    System_ID INTEGER NOT NULL,
    File_Name VARCHAR(255),
    STIG_Title TEXT,
    Import_Date DATETIME,
    Record_Count INTEGER
)
"@) | Out-Null
        
        # Vulnerabilities table
        $conn.ExecuteNonQuery(@"
CREATE TABLE Vulnerabilities (
    Vulnerability_ID AUTOINCREMENT PRIMARY KEY,
    File_ID INTEGER,
    Group_ID VARCHAR(100),
    Rule_ID VARCHAR(100),
    Rule_Title TEXT,
    Severity VARCHAR(20),
    Status VARCHAR(50),
    STIG_Name TEXT,
    CCI_References TEXT,
    NIST_Controls TEXT,
    Control_Families TEXT,
    Discussion TEXT,
    Check_Content TEXT,
    Fix_Text TEXT,
    Finding_Details TEXT,
    Comments TEXT,
    Import_Date DATETIME
)
"@) | Out-Null
        
        $conn.Disconnect()
        Write-Host "Database created successfully!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to create database: $($_.Exception.Message)"
        return $false
    }
}

#endregion

#region Site and System Management

function Get-Sites {
    try {
        Write-Host "  Debug: Getting sites from database..." -ForegroundColor DarkGray
        $result = $script:DatabaseConnection.ExecuteQuery("SELECT * FROM Sites ORDER BY Site_Name")
        Write-Host "  Debug: Query result type = $($result.GetType().Name), rows = $($result.Rows.Count)" -ForegroundColor DarkGray
        Write-Host "  Debug: Returning DataTable directly..." -ForegroundColor DarkGray
        return ,$result  # Comma operator to prevent unwrapping
    }
    catch {
        Write-Host "  Debug: Error in Get-Sites: $($_.Exception.Message)" -ForegroundColor Red
        Write-Error "Failed to get sites: $($_.Exception.Message)"
        return $null
    }
}

function Add-Site {
    param(
        [string]$SiteName,
        [string]$Description = "",
        [string]$Location = ""
    )
    
    try {
        Write-Host "Adding site: $SiteName" -ForegroundColor Cyan
        $nameEsc = $SiteName -replace "'", "''"
        $descEsc = $Description -replace "'", "''"
        $locEsc = $Location -replace "'", "''"
        
        $result = $script:DatabaseConnection.ExecuteNonQuery(@"
INSERT INTO Sites (Site_Name, Description, Location, Created_Date)
VALUES ('$nameEsc', '$descEsc', '$locEsc', Now())
"@)
        
        Write-Host "  Database reports $result row(s) affected" -ForegroundColor Gray
        Write-Host "✓ Site '$SiteName' added successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "✗ Failed to add site: $($_.Exception.Message)" -ForegroundColor Red
        Write-Error "Failed to add site: $($_.Exception.Message)"
        return $false
    }
}

function Update-Site {
    param(
        [int]$SiteId,
        [string]$SiteName,
        [string]$Description = "",
        [string]$Location = ""
    )
    
    try {
        Write-Host "Updating site ID $SiteId to: $SiteName" -ForegroundColor Cyan
        $nameEsc = $SiteName -replace "'", "''"
        $descEsc = $Description -replace "'", "''"
        $locEsc = $Location -replace "'", "''"
        
        $script:DatabaseConnection.ExecuteNonQuery(@"
UPDATE Sites 
SET Site_Name = '$nameEsc', Description = '$descEsc', Location = '$locEsc'
WHERE Site_ID = $SiteId
"@) | Out-Null
        
        Write-Host "✓ Site updated successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "✗ Failed to update site: $($_.Exception.Message)" -ForegroundColor Red
        Write-Error "Failed to update site: $($_.Exception.Message)"
        return $false
    }
}

function Remove-Site {
    param([int]$SiteId)
    
    try {
        Write-Host "Attempting to delete site ID: $SiteId" -ForegroundColor Cyan
        
        # Check if site has systems
        $systems = $script:DatabaseConnection.ExecuteQuery("SELECT COUNT(*) AS cnt FROM Systems WHERE Site_ID = $SiteId")
        if ($systems.Rows[0].cnt -gt 0) {
            Write-Host "✗ Cannot delete site: has $($systems.Rows[0].cnt) system(s)" -ForegroundColor Yellow
            return @{
                Success = $false
                Error = "Cannot delete site with existing systems. Delete systems first."
            }
        }
        
        $script:DatabaseConnection.ExecuteNonQuery("DELETE FROM Sites WHERE Site_ID = $SiteId") | Out-Null
        Write-Host "✓ Site deleted successfully" -ForegroundColor Green
        return @{ Success = $true }
    }
    catch {
        Write-Host "✗ Failed to delete site: $($_.Exception.Message)" -ForegroundColor Red
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-Systems {
    param([int]$SiteId = 0)
    
    try {
        if ($SiteId -gt 0) {
            return ,$script:DatabaseConnection.ExecuteQuery("SELECT * FROM Systems WHERE Site_ID = $SiteId ORDER BY System_Name")
        }
        else {
            return ,$script:DatabaseConnection.ExecuteQuery("SELECT * FROM Systems ORDER BY System_Name")
        }
    }
    catch {
        Write-Error "Failed to get systems: $($_.Exception.Message)"
        return $null
    }
}

function Add-System {
    param(
        [int]$SiteId,
        [string]$SystemName,
        [string]$Description = "",
        [string]$IPAddress = "",
        [string]$Hostname = ""
    )
    
    try {
        Write-Host "Adding system: $SystemName (Site ID: $SiteId)" -ForegroundColor Cyan
        $nameEsc = $SystemName -replace "'", "''"
        $descEsc = $Description -replace "'", "''"
        $ipEsc = $IPAddress -replace "'", "''"
        $hostEsc = $Hostname -replace "'", "''"
        
        $result = $script:DatabaseConnection.ExecuteNonQuery(@"
INSERT INTO Systems (Site_ID, System_Name, Description, IP_Address, Hostname, Created_Date)
VALUES ($SiteId, '$nameEsc', '$descEsc', '$ipEsc', '$hostEsc', Now())
"@)
        
        Write-Host "  Database reports $result row(s) affected" -ForegroundColor Gray
        Write-Host "✓ System '$SystemName' added successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "✗ Failed to add system: $($_.Exception.Message)" -ForegroundColor Red
        Write-Error "Failed to add system: $($_.Exception.Message)"
        return $false
    }
}

function Update-System {
    param(
        [int]$SystemId,
        [int]$SiteId,
        [string]$SystemName,
        [string]$Description = "",
        [string]$IPAddress = "",
        [string]$Hostname = ""
    )
    
    try {
        $nameEsc = $SystemName -replace "'", "''"
        $descEsc = $Description -replace "'", "''"
        $ipEsc = $IPAddress -replace "'", "''"
        $hostEsc = $Hostname -replace "'", "''"
        
        $script:DatabaseConnection.ExecuteNonQuery(@"
UPDATE Systems 
SET Site_ID = $SiteId, System_Name = '$nameEsc', Description = '$descEsc', 
    IP_Address = '$ipEsc', Hostname = '$hostEsc'
WHERE System_ID = $SystemId
"@) | Out-Null
        
        return $true
    }
    catch {
        Write-Error "Failed to update system: $($_.Exception.Message)"
        return $false
    }
}

function Remove-System {
    param([int]$SystemId)
    
    try {
        Write-Host "Attempting to delete system ID: $SystemId" -ForegroundColor Cyan
        
        # Check if system has STIG files
        $files = $script:DatabaseConnection.ExecuteQuery("SELECT COUNT(*) AS cnt FROM STIG_Files WHERE System_ID = $SystemId")
        if ($files.Rows[0].cnt -gt 0) {
            Write-Host "✗ Cannot delete system: has $($files.Rows[0].cnt) STIG file(s)" -ForegroundColor Yellow
            return @{
                Success = $false
                Error = "Cannot delete system with existing STIG imports. Delete imports first."
            }
        }
        
        $script:DatabaseConnection.ExecuteNonQuery("DELETE FROM Systems WHERE System_ID = $SystemId") | Out-Null
        Write-Host "✓ System deleted successfully" -ForegroundColor Green
        return @{ Success = $true }
    }
    catch {
        Write-Host "✗ Failed to delete system: $($_.Exception.Message)" -ForegroundColor Red
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

#endregion

#region CCI Import

function Import-CciMappings {
    param(
        [string]$XmlPath,
        [scriptblock]$ProgressCallback = $null,
        [string]$SourceFile = ""
    )
    
    try {
        [xml]$cciXml = Get-Content -Path $XmlPath -Raw
        $count = 0
        
        $ns = New-Object System.Xml.XmlNamespaceManager($cciXml.NameTable)
        $ns.AddNamespace("cci", "http://iase.disa.mil/cci")
        
        $cciItems = $cciXml.SelectNodes("//cci:cci_item", $ns)
        $totalItems = $cciItems.Count
        $currentIndex = 0
        
        # Clear existing mappings
        $script:DatabaseConnection.ExecuteNonQuery("DELETE FROM CCI_Mappings") | Out-Null
        
        foreach ($cciItem in $cciItems) {
            $currentIndex++
            $cciId = $cciItem.GetAttribute("id")
            $definition = $cciItem.SelectSingleNode("cci:definition", $ns).'#text'
            $nistControls = @()
            
            $references = $cciItem.SelectNodes("cci:references/cci:reference", $ns)
            foreach ($reference in $references) {
                $title = $reference.GetAttribute("title")
                $index = $reference.GetAttribute("index")
                
                if ($title -like '*800-53*' -and $index) {
                    $nistControls += $index
                }
            }
            
            if ($nistControls.Count -gt 0) {
                $nistStr = ($nistControls -join ', ') -replace "'", "''"
                $families = ($nistControls | ForEach-Object { 
                    if ($_ -match '^([A-Z]{2,3})-') { $matches[1] }
                } | Select-Object -Unique) -join ', '
                $desc = $definition -replace "'", "''"
                
                $script:DatabaseConnection.ExecuteNonQuery(@"
INSERT INTO CCI_Mappings (CCI_ID, NIST_Controls, Control_Families, Description, Import_Date, Source_File)
VALUES ('$cciId', '$nistStr', '$families', '$desc', Now(), '$SourceFile')
"@) | Out-Null
                $count++
            }
            
            # Call progress callback if provided (throttled to reduce jitter)
            if ($ProgressCallback) {
                # Only update UI every 10 items or on the last item to reduce jitter
                if (($currentIndex % 10 -eq 0) -or ($currentIndex -eq $totalItems)) {
                    $percent = [math]::Round(($currentIndex / $totalItems) * 100, 1)
                    & $ProgressCallback -Percent $percent -Current $currentIndex -Total $totalItems -Status "Processing CCI item $currentIndex of $totalItems (Imported: $count)"
                }
            }
        }
        
        return @{
            Success = $true
            Count = $count
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

#endregion

#region STIG Parsers

function Import-CklFile {
    param(
        [string]$Path,
        [int]$FileId,
        [scriptblock]$ProgressCallback = $null
    )
    
    try {
        [xml]$ckl = Get-Content -Path $Path -Raw
        $count = 0
        
        $stigName = $ckl.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA | 
            Where-Object { $_.SID_NAME -eq 'title' } | 
            Select-Object -ExpandProperty SID_DATA
        
        $vulns = $ckl.CHECKLIST.STIGS.iSTIG.VULN
        $totalVulns = $vulns.Count
        
        foreach ($vuln in $vulns) {
            $groupId = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Vuln_Num' }).ATTRIBUTE_DATA
            $ruleId = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Rule_ID' }).ATTRIBUTE_DATA
            $ruleTitle = (($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Rule_Title' }).ATTRIBUTE_DATA) -replace "'", "''"
            $severity = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Severity' }).ATTRIBUTE_DATA
            $discussion = (($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Vuln_Discuss' }).ATTRIBUTE_DATA) -replace "'", "''"
            $checkContent = (($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Check_Content' }).ATTRIBUTE_DATA) -replace "'", "''"
            $fixText = (($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Fix_Text' }).ATTRIBUTE_DATA.'#text') -replace "'", "''"
            
            $cciRefs = $vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'CCI_REF' }
            $cciStr = ""
            $nistStr = ""
            $familiesStr = ""
            
            if ($cciRefs) {
                $ccis = @($cciRefs | ForEach-Object { $_.ATTRIBUTE_DATA } | Where-Object { $_ })
                $cciStr = ($ccis -join ', ') -replace "'", "''"
                
                # Get NIST mappings
                $nistControls = [System.Collections.Generic.HashSet[string]]::new()
                $families = [System.Collections.Generic.HashSet[string]]::new()
                
                foreach ($cci in $ccis) {
                    $mapping = $script:DatabaseConnection.ExecuteQuery("SELECT NIST_Controls FROM CCI_Mappings WHERE CCI_ID = '$cci'")
                    if ($mapping.Rows.Count -gt 0) {
                        $controls = $mapping.Rows[0].NIST_Controls -split ', '
                        foreach ($ctrl in $controls) {
                            [void]$nistControls.Add($ctrl)
                            if ($ctrl -match '^([A-Z]{2,3})-') {
                                [void]$families.Add($matches[1])
                            }
                        }
                    }
                }
                
                $nistStr = (($nistControls | Sort-Object) -join ', ') -replace "'", "''"
                $familiesStr = (($families | Sort-Object) -join ', ') -replace "'", "''"
            }
            
            $status = $vuln.STATUS
            $findingDetails = ($vuln.FINDING_DETAILS -replace "'", "''")
            $comments = ($vuln.COMMENTS -replace "'", "''")
            $stigNameEsc = $stigName -replace "'", "''"
            
            $script:DatabaseConnection.ExecuteNonQuery(@"
INSERT INTO Vulnerabilities (File_ID, Group_ID, Rule_ID, Rule_Title, Severity, Status, STIG_Name,
    CCI_References, NIST_Controls, Control_Families, Discussion, Check_Content, Fix_Text, Finding_Details, Comments, Import_Date)
VALUES ($FileId, '$groupId', '$ruleId', '$ruleTitle', '$severity', '$status', '$stigNameEsc',
    '$cciStr', '$nistStr', '$familiesStr', '$discussion', '$checkContent', '$fixText', '$findingDetails', '$comments', NOW())
"@) | Out-Null
            $count++
        }
        
        return @{
            Success = $true
            Count = $count
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Import-CklbFile {
    param(
        [string]$Path,
        [int]$FileId
    )
    
    try {
        $jsonContent = Get-Content -Path $Path -Raw | ConvertFrom-Json
        $count = 0
        
        $stigName = $jsonContent.title
        
        foreach ($vuln in $jsonContent.stigs.rules) {
            $groupId = $vuln.group_id
            $ruleId = $vuln.rule_id
            $ruleTitle = ($vuln.rule_title -replace "'", "''")
            $severity = $vuln.severity
            $discussion = ($vuln.discussion -replace "'", "''")
            $checkContent = ($vuln.check_content -replace "'", "''")
            $fixText = ($vuln.fix_text -replace "'", "''")
            
            $cciList = @()
            if ($vuln.cci) { $cciList += @($vuln.cci) }
            if ($vuln.ccis) { $cciList += @($vuln.ccis) }
            if ($vuln.cci_refs) { $cciList += @($vuln.cci_refs) }
            $ccis = $cciList | Select-Object -Unique | Where-Object { $_ }
            
            $cciStr = ($ccis -join ', ') -replace "'", "''"
            $nistStr = ""
            $familiesStr = ""
            
            # Get NIST mappings
            $nistControls = [System.Collections.Generic.HashSet[string]]::new()
            $families = [System.Collections.Generic.HashSet[string]]::new()
            
            foreach ($cci in $ccis) {
                $mapping = $script:DatabaseConnection.ExecuteQuery("SELECT NIST_Controls FROM CCI_Mappings WHERE CCI_ID = '$cci'")
                if ($mapping.Rows.Count -gt 0) {
                    $controls = $mapping.Rows[0].NIST_Controls -split ', '
                    foreach ($ctrl in $controls) {
                        [void]$nistControls.Add($ctrl)
                        if ($ctrl -match '^([A-Z]{2,3})-') {
                            [void]$families.Add($matches[1])
                        }
                    }
                }
            }
            
            $nistStr = (($nistControls | Sort-Object) -join ', ') -replace "'", "''"
            $familiesStr = (($families | Sort-Object) -join ', ') -replace "'", "''"
            
            $status = $vuln.status
            $findingDetails = ($vuln.finding_details -replace "'", "''")
            $comments = ($vuln.comments -replace "'", "''")
            $stigNameEsc = $stigName -replace "'", "''"
            
            $script:DatabaseConnection.ExecuteNonQuery(@"
INSERT INTO Vulnerabilities (File_ID, Group_ID, Rule_ID, Rule_Title, Severity, Status, STIG_Name,
    CCI_References, NIST_Controls, Control_Families, Discussion, Check_Content, Fix_Text, Finding_Details, Comments, Import_Date)
VALUES ($FileId, '$groupId', '$ruleId', '$ruleTitle', '$severity', '$status', '$stigNameEsc',
    '$cciStr', '$nistStr', '$familiesStr', '$discussion', '$checkContent', '$fixText', '$findingDetails', '$comments', NOW())
"@) | Out-Null
            $count++
        }
        
        return @{
            Success = $true
            Count = $count
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

#endregion

#region UI Helpers

function New-StyledButton {
    param(
        [string]$Text,
        [System.Drawing.Point]$Location,
        [System.Drawing.Size]$Size,
        [System.Drawing.Color]$BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = $Location
    $button.Size = $Size
    $button.BackColor = $BackColor
    $button.ForeColor = [System.Drawing.Color]::White
    $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button.FlatAppearance.BorderSize = 0
    $button.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(
        [Math]::Min(255, $BackColor.R + 20),
        [Math]::Min(255, $BackColor.G + 20),
        [Math]::Min(255, $BackColor.B + 20)
    )
    $button.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand
    return $button
}

function Refresh-Dashboard {
    param($DashboardTab)

    # Clear existing controls
    $DashboardTab.Controls.Clear()

    # Overall statistics header
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Location = New-Object System.Drawing.Point(20, 10)
    $headerLabel.Size = New-Object System.Drawing.Size(400, 30)
    $headerLabel.Text = "Overall Security Compliance Dashboard"
    $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $DashboardTab.Controls.Add($headerLabel)

    # Get overall statistics
    $overallStats = @{
        TotalSites = 0
        TotalSystems = 0
        TotalFiles = 0
        TotalVulns = 0
        TotalCompliance = 0
    }

    try {
        $sitesData = $script:DatabaseConnection.ExecuteQuery("SELECT COUNT(*) AS cnt FROM Sites")
        $overallStats.TotalSites = $sitesData.Rows[0].cnt

        $systemsData = $script:DatabaseConnection.ExecuteQuery("SELECT COUNT(*) AS cnt FROM Systems")
        $overallStats.TotalSystems = $systemsData.Rows[0].cnt

        $filesData = $script:DatabaseConnection.ExecuteQuery("SELECT COUNT(*) AS cnt FROM STIG_Files")
        $overallStats.TotalFiles = $filesData.Rows[0].cnt

        $vulnsData = $script:DatabaseConnection.ExecuteQuery("SELECT COUNT(*) AS cnt FROM Vulnerabilities")
        $overallStats.TotalVulns = $vulnsData.Rows[0].cnt

        # Calculate overall compliance
        $complianceData = $script:DatabaseConnection.ExecuteQuery(@"
SELECT
    COUNT(*) AS Total,
    SUM(IIF(Status='NotAFinding' OR Status='Not_A_Finding' OR Status='Not_Applicable', 1, 0)) AS Compliant
FROM Vulnerabilities
"@)
        if ($complianceData.Rows.Count -gt 0 -and $complianceData.Rows[0].Total -gt 0) {
            $total = $complianceData.Rows[0].Total
            $compliant = if ($complianceData.Rows[0].Compliant -is [DBNull]) { 0 } else { $complianceData.Rows[0].Compliant }
            $overallStats.TotalCompliance = [math]::Round(($compliant / $total) * 100, 1)
        }
    }
    catch {
        Write-Warning "Error loading overall statistics: $_"
    }

    # Overall stat cards (compact)
    $cardY = 50
    $cardX = 20
    $cardWidth = 140
    $cardHeight = 80
    $cardSpacing = 155

    $overallCards = @(
        @{Label="Sites"; Value=$overallStats.TotalSites; Color=[System.Drawing.Color]::FromArgb(0, 120, 215)},
        @{Label="Systems"; Value=$overallStats.TotalSystems; Color=[System.Drawing.Color]::FromArgb(0, 120, 215)},
        @{Label="STIG Files"; Value=$overallStats.TotalFiles; Color=[System.Drawing.Color]::FromArgb(102, 51, 153)},
        @{Label="Total Findings"; Value=$overallStats.TotalVulns; Color=[System.Drawing.Color]::FromArgb(23, 162, 184)},
        @{Label="Overall Compliance"; Value="$($overallStats.TotalCompliance)%"; Color=[System.Drawing.Color]::FromArgb(40, 167, 69)}
    )

    for ($i = 0; $i -lt $overallCards.Count; $i++) {
        $card = New-Object System.Windows.Forms.Panel
        $card.Location = New-Object System.Drawing.Point(($cardX + $i * $cardSpacing), $cardY)
        $card.Size = New-Object System.Drawing.Size($cardWidth, $cardHeight)
        $card.BackColor = $overallCards[$i].Color

        $labelTitle = New-Object System.Windows.Forms.Label
        $labelTitle.Location = New-Object System.Drawing.Point(5, 5)
        $labelTitle.Size = New-Object System.Drawing.Size(130, 20)
        $labelTitle.Text = $overallCards[$i].Label
        $labelTitle.ForeColor = [System.Drawing.Color]::White
        $labelTitle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $card.Controls.Add($labelTitle)

        $labelValue = New-Object System.Windows.Forms.Label
        $labelValue.Location = New-Object System.Drawing.Point(5, 30)
        $labelValue.Size = New-Object System.Drawing.Size(130, 45)
        $labelValue.Text = $overallCards[$i].Value
        $labelValue.ForeColor = [System.Drawing.Color]::White
        $labelValue.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
        $labelValue.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
        $card.Controls.Add($labelValue)

        $DashboardTab.Controls.Add($card)
    }

    # Site-specific cards section
    $siteCardsLabel = New-Object System.Windows.Forms.Label
    $siteCardsLabel.Location = New-Object System.Drawing.Point(20, 150)
    $siteCardsLabel.Size = New-Object System.Drawing.Size(800, 25)
    $siteCardsLabel.Text = "Sites & Systems Overview"
    $siteCardsLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $DashboardTab.Controls.Add($siteCardsLabel)

    # Get all sites with their statistics
    try {
        $sitesData = $script:DatabaseConnection.ExecuteQuery("SELECT Site_ID, Site_Name FROM Sites ORDER BY Site_Name")

        $siteCardY = 180
        $siteCardX = 20
        $siteCardWidth = 250
        $siteCardHeight = 160
        $siteCardSpacing = 270

        $siteIndex = 0
        foreach ($siteRow in $sitesData.Rows) {
            $siteId = $siteRow.Site_ID
            $siteName = $siteRow.Site_Name

            # Get statistics for this site using simpler queries
            $systemCount = 0
            $fileCount = 0
            $vulnCount = 0
            $openCount = 0
            $highCount = 0
            $compliance = 0

            try {
                # Get system count
                $sysCountData = $script:DatabaseConnection.ExecuteQuery("SELECT COUNT(*) AS cnt FROM Systems WHERE Site_ID = $siteId")
                $systemCount = $sysCountData.Rows[0].cnt

                # Get file count for this site
                $fileCountData = $script:DatabaseConnection.ExecuteQuery(@"
SELECT COUNT(*) AS cnt
FROM STIG_Files s
INNER JOIN Systems st ON s.System_ID = st.System_ID
WHERE st.Site_ID = $siteId
"@)
                $fileCount = $fileCountData.Rows[0].cnt

                # Get vulnerability statistics for this site
                $vulnStatsData = $script:DatabaseConnection.ExecuteQuery(@"
SELECT
    COUNT(*) AS Total,
    SUM(IIF(v.Status='Open', 1, 0)) AS [Open],
    SUM(IIF(v.Severity='high' OR v.Severity='critical', 1, 0)) AS HighCrit,
    SUM(IIF(v.Status='NotAFinding' OR v.Status='Not_A_Finding' OR v.Status='Not_Applicable', 1, 0)) AS Compliant
FROM (Vulnerabilities v
INNER JOIN STIG_Files s ON v.File_ID = s.File_ID)
INNER JOIN Systems st ON s.System_ID = st.System_ID
WHERE st.Site_ID = $siteId
"@)

                if ($vulnStatsData.Rows.Count -gt 0) {
                    $vulnCount = if ($vulnStatsData.Rows[0].Total -is [DBNull]) { 0 } else { $vulnStatsData.Rows[0].Total }
                    $openCount = if ($vulnStatsData.Rows[0].Open -is [DBNull]) { 0 } else { $vulnStatsData.Rows[0].Open }
                    $highCount = if ($vulnStatsData.Rows[0].HighCrit -is [DBNull]) { 0 } else { $vulnStatsData.Rows[0].HighCrit }

                    # Calculate compliance
                    if ($vulnCount -gt 0) {
                        $compliantCount = if ($vulnStatsData.Rows[0].Compliant -is [DBNull]) { 0 } else { $vulnStatsData.Rows[0].Compliant }
                        $compliance = [math]::Round(($compliantCount / $vulnCount) * 100, 1)
                    }
                }
            }
            catch {
                Write-Warning "Error loading stats for site $siteName : $_"
            }

            # Determine card color based on compliance
            $cardColor = [System.Drawing.Color]::FromArgb(108, 117, 125)  # Gray default
            if ($vulnCount -gt 0) {
                if ($compliance -ge 90) {
                    $cardColor = [System.Drawing.Color]::FromArgb(40, 167, 69)  # Green
                }
                elseif ($compliance -ge 70) {
                    $cardColor = [System.Drawing.Color]::FromArgb(255, 193, 7)  # Yellow/Orange
                }
                else {
                    $cardColor = [System.Drawing.Color]::FromArgb(220, 53, 69)  # Red
                }
            }

            # Create site card
            $col = $siteIndex % 4
            $row = [math]::Floor($siteIndex / 4)

            $siteCard = New-Object System.Windows.Forms.Panel
            $siteCard.Location = New-Object System.Drawing.Point(($siteCardX + $col * $siteCardSpacing), ($siteCardY + $row * 180))
            $siteCard.Size = New-Object System.Drawing.Size($siteCardWidth, $siteCardHeight)
            $siteCard.BackColor = $cardColor
            $siteCard.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

            # Site name header
            $siteNameLabel = New-Object System.Windows.Forms.Label
            $siteNameLabel.Location = New-Object System.Drawing.Point(10, 8)
            $siteNameLabel.Size = New-Object System.Drawing.Size(230, 25)
            $siteNameLabel.Text = $siteName
            $siteNameLabel.ForeColor = [System.Drawing.Color]::White
            $siteNameLabel.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
            $siteCard.Controls.Add($siteNameLabel)

            # Compliance percentage - large
            $complianceLabel = New-Object System.Windows.Forms.Label
            $complianceLabel.Location = New-Object System.Drawing.Point(10, 35)
            $complianceLabel.Size = New-Object System.Drawing.Size(230, 40)
            $complianceLabel.Text = "$compliance% Compliant"
            $complianceLabel.ForeColor = [System.Drawing.Color]::White
            $complianceLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
            $complianceLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
            $siteCard.Controls.Add($complianceLabel)

            # Statistics text
            $statsText = @"
Systems: $systemCount | STIG Files: $fileCount
Total Findings: $vulnCount
Open: $openCount | High/Critical: $highCount
"@
            $statsLabel = New-Object System.Windows.Forms.Label
            $statsLabel.Location = New-Object System.Drawing.Point(10, 80)
            $statsLabel.Size = New-Object System.Drawing.Size(230, 70)
            $statsLabel.Text = $statsText
            $statsLabel.ForeColor = [System.Drawing.Color]::White
            $statsLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $siteCard.Controls.Add($statsLabel)

            $DashboardTab.Controls.Add($siteCard)
            $siteIndex++
        }
    }
    catch {
        Write-Warning "Error loading site cards: $_"
    }

    # Recent imports list
    $recentLabel = New-Object System.Windows.Forms.Label
    $recentLabel.Location = New-Object System.Drawing.Point(20, 425)
    $recentLabel.Size = New-Object System.Drawing.Size(800, 25)
    $recentLabel.Text = "Recent Imports"
    $recentLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $DashboardTab.Controls.Add($recentLabel)

    $recentGrid = New-Object System.Windows.Forms.DataGridView
    $recentGrid.Location = New-Object System.Drawing.Point(20, 455)
    $recentGrid.Size = New-Object System.Drawing.Size(1130, 200)
    $recentGrid.ReadOnly = $true
    $recentGrid.AllowUserToAddRows = $false
    $recentGrid.SelectionMode = 'FullRowSelect'
    $recentGrid.BackgroundColor = [System.Drawing.Color]::White
    $recentGrid.AutoSizeColumnsMode = 'Fill'

    try {
        $recentData = $script:DatabaseConnection.ExecuteQuery(@"
SELECT TOP 10
    s.File_Name AS [File Name],
    s.STIG_Title AS [STIG Title],
    st.System_Name AS [System],
    si.Site_Name AS [Site],
    s.Import_Date AS [Import Date],
    s.Record_Count AS [Findings]
FROM (STIG_Files s
LEFT JOIN Systems st ON s.System_ID = st.System_ID)
LEFT JOIN Sites si ON st.Site_ID = si.Site_ID
ORDER BY s.Import_Date DESC
"@)
        $recentGrid.DataSource = $recentData
    }
    catch {
        Write-Warning "Error loading recent imports: $_"
    }

    $DashboardTab.Controls.Add($recentGrid)
}

function Refresh-BrowseData {
    param(
        $DataGrid,
        $StatusLabel,
        $SiteCombo = $null,
        $SystemCombo = $null,
        $SeverityCombo = $null,
        $StatusCombo = $null
    )

    try {
        $StatusLabel.Text = "Loading data..."
        $StatusLabel.Refresh()

        # Build WHERE clause based on filters
        $whereClause = ""

        if ($SiteCombo -and $SiteCombo.SelectedValue) {
            $siteId = [int]$SiteCombo.SelectedValue
            if ($whereClause) { $whereClause += " AND " } else { $whereClause = "WHERE " }
            $whereClause += "st.Site_ID = $siteId"
        }

        if ($SystemCombo -and $SystemCombo.SelectedValue) {
            $systemId = [int]$SystemCombo.SelectedValue
            if ($whereClause) { $whereClause += " AND " } else { $whereClause = "WHERE " }
            $whereClause += "st.System_ID = $systemId"
        }

        if ($SeverityCombo -and $SeverityCombo.SelectedItem -and $SeverityCombo.SelectedItem -ne "All") {
            $severity = $SeverityCombo.SelectedItem.ToString()
            if ($whereClause) { $whereClause += " AND " } else { $whereClause = "WHERE " }
            $whereClause += "v.Severity = '$severity'"
        }

        if ($StatusCombo -and $StatusCombo.SelectedItem -and $StatusCombo.SelectedItem -ne "All") {
            $status = $StatusCombo.SelectedItem.ToString()
            if ($whereClause) { $whereClause += " AND " } else { $whereClause = "WHERE " }
            $whereClause += "v.Status = '$status'"
        }
        
        $query = @"
SELECT
    v.Group_ID AS [Vuln ID],
    v.Rule_ID AS [Rule ID],
    v.Rule_Title AS [Title],
    v.Severity,
    v.Status,
    v.NIST_Controls AS [NIST Controls],
    v.Control_Families AS [Families],
    v.CCI_References AS [CCIs],
    v.STIG_Name AS [STIG Name],
    s.File_Name AS [Source File],
    st.System_Name AS [System],
    si.Site_Name AS [Site]
FROM ((Vulnerabilities v
LEFT JOIN STIG_Files s ON v.File_ID = s.File_ID)
LEFT JOIN Systems st ON s.System_ID = st.System_ID)
LEFT JOIN Sites si ON st.Site_ID = si.Site_ID
$whereClause
ORDER BY v.Severity DESC, v.Status
"@
        
        Write-Host "Debug: Executing query: $query" -ForegroundColor DarkGray
        
        # First, let's check if we have any data at all
        $testQuery = "SELECT COUNT(*) AS vuln_count FROM Vulnerabilities"
        $vulnCount = $script:DatabaseConnection.ExecuteQuery($testQuery)
        Write-Host "Debug: Total vulnerabilities in database: $($vulnCount.Rows[0].vuln_count)" -ForegroundColor Yellow
        
        $testQuery2 = "SELECT COUNT(*) AS file_count FROM STIG_Files"
        $fileCount = $script:DatabaseConnection.ExecuteQuery($testQuery2)
        Write-Host "Debug: Total STIG files in database: $($fileCount.Rows[0].file_count)" -ForegroundColor Yellow
        
        $testQuery3 = "SELECT COUNT(*) AS system_count FROM Systems"
        $systemCount = $script:DatabaseConnection.ExecuteQuery($testQuery3)
        Write-Host "Debug: Total systems in database: $($systemCount.Rows[0].system_count)" -ForegroundColor Yellow
        
        # Check the JOIN relationships
        $joinTestQuery = "SELECT DISTINCT s.System_ID, st.System_ID as st_system_id FROM STIG_Files s LEFT JOIN Systems st ON s.System_ID = st.System_ID"
        $joinResults = $script:DatabaseConnection.ExecuteQuery($joinTestQuery)
        Write-Host "Debug: JOIN test - STIG_Files.System_ID values: $($joinResults.Rows | ForEach-Object { $_.System_ID } | Sort-Object | Out-String)" -ForegroundColor Yellow
        Write-Host "Debug: JOIN test - Systems.System_ID values: $($joinResults.Rows | ForEach-Object { $_.st_system_id } | Sort-Object | Out-String)" -ForegroundColor Yellow
        
        # Check if there are any vulnerabilities linked to STIG files
        $vulnJoinTest = "SELECT COUNT(*) as [CountResult] FROM Vulnerabilities v INNER JOIN STIG_Files s ON v.File_ID = s.File_ID"
        $vulnJoinCount = $script:DatabaseConnection.ExecuteQuery($vulnJoinTest)
        Write-Host "Debug: Vulnerabilities linked to STIG files: $($vulnJoinCount.Rows[0].CountResult)" -ForegroundColor Yellow

        # Check what File_IDs exist in Vulnerabilities vs STIG_Files
        $vulnFileIds = $script:DatabaseConnection.ExecuteQuery("SELECT DISTINCT File_ID FROM Vulnerabilities ORDER BY File_ID")
        $vulnFileIdList = ($vulnFileIds.Rows | ForEach-Object { $_.File_ID }) -join ', '
        Write-Host "Debug: File_IDs in Vulnerabilities: $vulnFileIdList" -ForegroundColor Cyan

        $stigFileIds = $script:DatabaseConnection.ExecuteQuery("SELECT File_ID FROM STIG_Files ORDER BY File_ID")
        $stigFileIdList = ($stigFileIds.Rows | ForEach-Object { $_.File_ID }) -join ', '
        Write-Host "Debug: File_IDs in STIG_Files: $stigFileIdList" -ForegroundColor Cyan

        $data = $script:DatabaseConnection.ExecuteQuery($query)
        Write-Host "Debug: Query returned $($data.Rows.Count) rows" -ForegroundColor DarkGray
        
        $DataGrid.DataSource = $data
        $DataGrid.AutoSizeColumnsMode = 'Fill'

        # Color code severity and status columns
        foreach ($row in $DataGrid.Rows) {
            # Severity color coding
            $severity = $row.Cells["Severity"].Value
            if ($severity) {
                $sevLower = $severity.ToString().ToLower()
                if ($sevLower -eq "high" -or $sevLower -eq "critical") {
                    # Red for high/critical
                    $row.Cells["Severity"].Style.BackColor = [System.Drawing.Color]::FromArgb(255, 100, 100)
                    $row.Cells["Severity"].Style.ForeColor = [System.Drawing.Color]::White
                }
                elseif ($sevLower -eq "medium") {
                    # Orange for medium
                    $row.Cells["Severity"].Style.BackColor = [System.Drawing.Color]::FromArgb(255, 165, 0)
                    $row.Cells["Severity"].Style.ForeColor = [System.Drawing.Color]::White
                }
                elseif ($sevLower -eq "low") {
                    # Yellow for low
                    $row.Cells["Severity"].Style.BackColor = [System.Drawing.Color]::FromArgb(255, 215, 0)
                    $row.Cells["Severity"].Style.ForeColor = [System.Drawing.Color]::Black
                }
            }

            # Status color coding
            $status = $row.Cells["Status"].Value
            if ($status) {
                $statusLower = $status.ToString().ToLower().Replace("_", "")
                if ($statusLower -eq "open") {
                    # Red for Open
                    $row.Cells["Status"].Style.BackColor = [System.Drawing.Color]::FromArgb(255, 100, 100)
                    $row.Cells["Status"].Style.ForeColor = [System.Drawing.Color]::White
                }
                elseif ($statusLower -eq "notreviewed" -or $statusLower -eq "not reviewed") {
                    # Blue for Not_Reviewed
                    $row.Cells["Status"].Style.BackColor = [System.Drawing.Color]::FromArgb(100, 149, 237)
                    $row.Cells["Status"].Style.ForeColor = [System.Drawing.Color]::White
                }
                elseif ($statusLower -eq "notafinding" -or $statusLower -eq "not a finding" -or $statusLower -eq "not_a_finding") {
                    # Green for NotAFinding
                    $row.Cells["Status"].Style.BackColor = [System.Drawing.Color]::FromArgb(60, 179, 113)
                    $row.Cells["Status"].Style.ForeColor = [System.Drawing.Color]::White
                }
                elseif ($statusLower -eq "notapplicable" -or $statusLower -eq "not applicable" -or $statusLower -eq "not_applicable") {
                    # Gray for Not_Applicable
                    $row.Cells["Status"].Style.BackColor = [System.Drawing.Color]::FromArgb(169, 169, 169)
                    $row.Cells["Status"].Style.ForeColor = [System.Drawing.Color]::White
                }
            }
        }
        
        $StatusLabel.Text = "Loaded $($data.Rows.Count) vulnerabilities"
        $StatusLabel.ForeColor = [System.Drawing.Color]::Green
    }
    catch {
        $errorMsg = $_.Exception.Message
        $StatusLabel.Text = "Error loading data: $errorMsg"
        $StatusLabel.ForeColor = [System.Drawing.Color]::Red
        Write-Host "ERROR in Refresh-BrowseData: $errorMsg" -ForegroundColor Red
        Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    }
}

#endregion

#region CCI Management Functions

function Update-CciSchema {
    try {
        Write-Host "Checking CCI schema..." -ForegroundColor Yellow
        
        # Check if new columns exist
        $checkColumns = $script:DatabaseConnection.ExecuteQuery("SELECT TOP 1 * FROM CCI_Mappings")
        $hasImportDate = $checkColumns.Columns.Contains("Import_Date")
        $hasSourceFile = $checkColumns.Columns.Contains("Source_File")
        
        if (-not $hasImportDate) {
            Write-Host "Adding Import_Date column to CCI_Mappings..." -ForegroundColor Yellow
            $script:DatabaseConnection.ExecuteNonQuery("ALTER TABLE CCI_Mappings ADD COLUMN Import_Date DATETIME") | Out-Null
        }
        
        if (-not $hasSourceFile) {
            Write-Host "Adding Source_File column to CCI_Mappings..." -ForegroundColor Yellow
            $script:DatabaseConnection.ExecuteNonQuery("ALTER TABLE CCI_Mappings ADD COLUMN Source_File VARCHAR(255)") | Out-Null
        }
        
        Write-Host "CCI schema updated successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Error updating CCI schema: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-CciStatus {
    try {
        # First check if the new columns exist, if not use basic query
        $checkColumns = $script:DatabaseConnection.ExecuteQuery("SELECT TOP 1 * FROM CCI_Mappings")
        $hasNewColumns = $checkColumns.Columns.Contains("Import_Date") -and $checkColumns.Columns.Contains("Source_File")
        
        if ($hasNewColumns) {
            $result = $script:DatabaseConnection.ExecuteQuery("SELECT COUNT(*) AS cnt, MAX(Import_Date) AS last_import, MAX(Source_File) AS last_source_file FROM CCI_Mappings")
            
            if ($result.Rows.Count -gt 0) {
                $count = $result.Rows[0].cnt
                $lastImport = $result.Rows[0].last_import
                $sourceFile = $result.Rows[0].last_source_file
                
                if ($count -gt 0) {
                    $status = "CCI Data Loaded: $count mappings`nLast Import: $lastImport`nSource File: $sourceFile"
                    return @{
                        HasData = $true
                        Count = $count
                        LastImport = $lastImport
                        SourceFile = $sourceFile
                        StatusText = $status
                    }
                }
            }
        } else {
            # Fallback to basic query for older schema
            $result = $script:DatabaseConnection.ExecuteQuery("SELECT COUNT(*) AS cnt FROM CCI_Mappings")
            
            if ($result.Rows.Count -gt 0) {
                $count = $result.Rows[0].cnt
                
                if ($count -gt 0) {
                    $status = "CCI Data Loaded: $count mappings (Legacy format - no import date available)"
                    return @{
                        HasData = $true
                        Count = $count
                        LastImport = "Unknown"
                        SourceFile = "Unknown"
                        StatusText = $status
                    }
                }
            }
        }
        
        return @{
            HasData = $false
            Count = 0
            StatusText = "No CCI data loaded"
        }
    }
    catch {
        Write-Host "Error getting CCI status: $($_.Exception.Message)" -ForegroundColor Red
        return @{
            HasData = $false
            Count = 0
            StatusText = "Error loading CCI status: $($_.Exception.Message)"
        }
    }
}

function Clear-CciData {
    try {
        $result = $script:DatabaseConnection.ExecuteNonQuery("DELETE FROM CCI_Mappings")
        Write-Host "CCI data cleared successfully" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Error clearing CCI data: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Refresh-CciPreview {
    param(
        [System.Windows.Forms.DataGridView]$DataGrid
    )
    
    try {
        # Check if new columns exist
        $checkColumns = $script:DatabaseConnection.ExecuteQuery("SELECT TOP 1 * FROM CCI_Mappings")
        $hasNewColumns = $checkColumns.Columns.Contains("Import_Date") -and $checkColumns.Columns.Contains("Source_File")
        
        if ($hasNewColumns) {
            $data = $script:DatabaseConnection.ExecuteQuery("SELECT TOP 50 CCI_ID, NIST_Controls, Control_Families, Import_Date, Source_File FROM CCI_Mappings ORDER BY CCI_ID")
        } else {
            # Fallback for legacy schema
            $data = $script:DatabaseConnection.ExecuteQuery("SELECT TOP 50 CCI_ID, NIST_Controls, Control_Families FROM CCI_Mappings ORDER BY CCI_ID")
        }
        
        $DataGrid.DataSource = $data
        Write-Host "CCI preview refreshed with $($data.Rows.Count) records" -ForegroundColor Green
    }
    catch {
        Write-Host "Error refreshing CCI preview: $($_.Exception.Message)" -ForegroundColor Red
        $DataGrid.DataSource = $null
    }
}

function Update-CciStatus {
    param(
        [System.Windows.Forms.Label]$StatusLabel,
        [System.Windows.Forms.DataGridView]$DataGrid
    )
    
    $status = Get-CciStatus
    $StatusLabel.Text = $status.StatusText
    
    if ($status.HasData) {
        $StatusLabel.ForeColor = [System.Drawing.Color]::DarkGreen
        Refresh-CciPreview -DataGrid $DataGrid
    } else {
        $StatusLabel.ForeColor = [System.Drawing.Color]::DarkRed
        $DataGrid.DataSource = $null
    }
}

#endregion

#region UI Helper Functions

function Refresh-BrowseFilters {
    param(
        [System.Windows.Forms.ComboBox]$SiteCombo,
        [System.Windows.Forms.ComboBox]$SystemCombo
    )
    
    Write-Host "Refreshing browse filters..." -ForegroundColor Cyan
    
    try {
        # Refresh sites
        $SiteCombo.DataSource = $null
        $sites = Get-Sites
        if ($sites -and $sites.Rows.Count -gt 0) {
            $siteItems = New-Object System.Collections.ArrayList
            foreach ($row in $sites.Rows) {
                $siteId = $row["Site_ID"]
                $siteName = $row["Site_Name"]
                $name = if ($siteName -is [DBNull] -or [string]::IsNullOrEmpty($siteName)) { '' } else { $siteName.ToString() }
                $null = $siteItems.Add([pscustomobject]@{ Site_ID = [int]$siteId; DisplayName = $name })
            }
            $SiteCombo.DisplayMember = 'DisplayName'
            $SiteCombo.ValueMember = 'Site_ID'
            $SiteCombo.DataSource = $siteItems
            Write-Host "  Loaded $($sites.Rows.Count) site(s) into browse filter" -ForegroundColor Gray
        }
        else {
            Write-Host "  No sites available for browse filter" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  Error loading sites: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    try {
        # Refresh systems based on selected site
        $SystemCombo.DataSource = $null
        $selectedSiteId = if ($SiteCombo.SelectedValue) { [int]$SiteCombo.SelectedValue } else { 0 }
        if ($selectedSiteId -gt 0) {
            $systems = Get-Systems -SiteId $selectedSiteId
            if ($systems -and $systems.Rows.Count -gt 0) {
                $sysItems = New-Object System.Collections.ArrayList
                foreach ($row in $systems.Rows) {
                    $name = if ($row.System_Name -is [DBNull]) { '' } else { $row.System_Name.ToString() }
                    $null = $sysItems.Add([pscustomobject]@{ System_ID = [int]$row.System_ID; DisplayName = $name })
                }
                $SystemCombo.DisplayMember = 'DisplayName'
                $SystemCombo.ValueMember = 'System_ID'
                $SystemCombo.DataSource = $sysItems
                Write-Host "  Loaded $($systems.Rows.Count) system(s) into browse filter" -ForegroundColor Gray
            }
            else {
                Write-Host "  No systems found for selected site" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "  No site selected - select a site to load systems" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  Error loading systems: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "✓ Browse filters refreshed" -ForegroundColor Green
}


function Refresh-ImportContextSelectors {
    param(
        [System.Windows.Forms.ComboBox]$ImportSiteCombo,
        [System.Windows.Forms.ComboBox]$ImportSystemCombo
    )
    
    Write-Host "Refreshing import context selectors..." -ForegroundColor Cyan
    
    $currentSiteId = if ($ImportSiteCombo.SelectedValue) { [int]$ImportSiteCombo.SelectedValue } else { 0 }
    $currentSystemId = if ($ImportSystemCombo.SelectedValue) { [int]$ImportSystemCombo.SelectedValue } else { 0 }
    
    # Refresh sites using data binding
    try {
        $ImportSiteCombo.DataSource = $null
        $sites = Get-Sites
        if ($sites -and ($sites -is [System.Data.DataTable]) -and $sites.Rows.Count -gt 0) {
            Write-Host "  Loaded $($sites.Rows.Count) site(s) into import dropdown" -ForegroundColor Gray
            $siteItems = New-Object System.Collections.ArrayList
            foreach ($row in $sites.Rows) {
                $name = if ($row.Site_Name -is [DBNull]) { '' } else { $row.Site_Name.ToString() }
                $null = $siteItems.Add([pscustomobject]@{ Site_ID = [int]$row.Site_ID; DisplayName = $name })
            }
            $ImportSiteCombo.DisplayMember = 'DisplayName'
            $ImportSiteCombo.ValueMember = 'Site_ID'
            $ImportSiteCombo.DataSource = $siteItems
            
            # Restore selection
            if ($currentSiteId -gt 0) {
                $ImportSiteCombo.SelectedValue = $currentSiteId
            }
            elseif ($ImportSiteCombo.Items.Count -gt 0) {
                $ImportSiteCombo.SelectedIndex = 0
            }
        }
        else {
            Write-Host "  No sites available for import" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  Error loading sites for import: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Refresh systems for selected site using data binding
    try {
        $ImportSystemCombo.DataSource = $null
        $selectedSiteId = if ($ImportSiteCombo.SelectedValue) { [int]$ImportSiteCombo.SelectedValue } else { 0 }
        if ($selectedSiteId -gt 0) {
            $systems = Get-Systems -SiteId $selectedSiteId
            if ($systems -and $systems.Rows.Count -gt 0) {
                Write-Host "  Loaded $($systems.Rows.Count) system(s) into import dropdown" -ForegroundColor Gray
                $sysItems = New-Object System.Collections.ArrayList
                foreach ($row in $systems.Rows) {
                    $name = if ($row.System_Name -is [DBNull]) { '' } else { $row.System_Name.ToString() }
                    $null = $sysItems.Add([pscustomobject]@{ System_ID = [int]$row.System_ID; DisplayName = $name })
                }
                $ImportSystemCombo.DisplayMember = 'DisplayName'
                $ImportSystemCombo.ValueMember = 'System_ID'
                $ImportSystemCombo.DataSource = $sysItems
                
                # Restore selection
                if ($currentSystemId -gt 0) {
                    $ImportSystemCombo.SelectedValue = $currentSystemId
                }
                elseif ($ImportSystemCombo.Items.Count -gt 0) {
                    $ImportSystemCombo.SelectedIndex = 0
                }
            }
            else {
                Write-Host "  No systems found for selected site" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "  No site selected for import" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  Error loading systems for import: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "✓ Import context selectors refreshed" -ForegroundColor Green
}

function Update-ImportStatus {
    param(
        [System.Windows.Forms.Label]$CciStatusLabel,
        [System.Windows.Forms.Label]$StigStatusLabel,
        [System.Windows.Forms.ComboBox]$ImportSiteCombo,
        [System.Windows.Forms.ComboBox]$ImportSystemCombo
    )
    
    $siteSelected = $ImportSiteCombo.SelectedValue -ne $null
    $systemSelected = $ImportSystemCombo.SelectedValue -ne $null
    
    if ($siteSelected -and $systemSelected) {
        $siteName = $ImportSiteCombo.Text
        $systemName = $ImportSystemCombo.Text
        $CciStatusLabel.Text = "Ready to import CCI mappings for: $systemName ($siteName)"
        $StigStatusLabel.Text = "Ready to import STIG files for: $systemName ($siteName)"
        $CciStatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
        $StigStatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
    }
    elseif ($siteSelected) {
        $CciStatusLabel.Text = "Please select a system to continue"
        $StigStatusLabel.Text = "Please select a system to continue"
        $CciStatusLabel.ForeColor = [System.Drawing.Color]::Orange
        $StigStatusLabel.ForeColor = [System.Drawing.Color]::Orange
    }
    else {
        $CciStatusLabel.Text = "Please select a site and system first"
        $StigStatusLabel.Text = "Please select a site and system first"
        $CciStatusLabel.ForeColor = [System.Drawing.Color]::Gray
        $StigStatusLabel.ForeColor = [System.Drawing.Color]::Gray
    }
}

function Refresh-ManagementLists {
    param(
        [System.Windows.Forms.ListBox]$SitesListBox,
        [System.Windows.Forms.ListBox]$SystemsListBox
    )
    
    Write-Host "Refreshing management lists..." -ForegroundColor Cyan
    if (-not $SitesListBox -or -not $SystemsListBox) { 
        Write-Host "  Debug: Missing listboxes - SitesListBox: $($SitesListBox -ne $null), SystemsListBox: $($SystemsListBox -ne $null)" -ForegroundColor Red
        return 
    }
    
    # Set flag to prevent event loops
    $script:IsRefreshingMgmt = $true
    
    # Build simple objects for binding (avoids DataRow display issues)
    $SitesListBox.DataSource = $null
    $SystemsListBox.DataSource = $null
    $sites = Get-Sites
    if ($sites -and $sites.Rows.Count -gt 0) {
        Write-Host "  Found $($sites.Rows.Count) site(s)" -ForegroundColor Gray
        $siteItems = New-Object System.Collections.ArrayList
        foreach ($row in $sites.Rows) {
            $name = if ($row.Site_Name -is [DBNull]) { '' } else { $row.Site_Name.ToString() }
            $loc = if ($row.Location -is [DBNull]) { '' } else { $row.Location.ToString() }
            $display = if ($loc) { "$name - $loc" } else { $name }
            $null = $siteItems.Add([pscustomobject]@{ Site_ID = [int]$row.Site_ID; DisplayName = $display })
        }
        $SitesListBox.DisplayMember = 'DisplayName'
        $SitesListBox.ValueMember = 'Site_ID'
        $SitesListBox.DataSource = $siteItems
        if ($SitesListBox.SelectedIndex -eq -1 -and $siteItems.Count -gt 0) { $SitesListBox.SelectedIndex = 0 }
        
        # Bind systems for selected site
        $siteId = if ($SitesListBox.SelectedIndex -ge 0) { [int]$SitesListBox.SelectedValue } else { 0 }
        if ($siteId -gt 0) {
            $systems = Get-Systems -SiteId $siteId
            if ($systems -and $systems.Rows.Count -gt 0) {
                Write-Host "  Found $($systems.Rows.Count) system(s) for selected site" -ForegroundColor Gray
                $sysItems = New-Object System.Collections.ArrayList
                foreach ($row in $systems.Rows) {
                    $name = if ($row.System_Name -is [DBNull]) { '' } else { $row.System_Name.ToString() }
                    $hostname = if ($row.Hostname -is [DBNull]) { '' } else { $row.Hostname.ToString() }
                    $display = if ($hostname) { "$name ($hostname)" } else { $name }
                    $null = $sysItems.Add([pscustomobject]@{ System_ID = [int]$row.System_ID; DisplayName = $display })
                }
                $SystemsListBox.DisplayMember = 'DisplayName'
                $SystemsListBox.ValueMember = 'System_ID'
                $SystemsListBox.DataSource = $sysItems
            }
        }
    }
    else {
        Write-Host "  No sites found - use '+ Add Site' to create one" -ForegroundColor Yellow
    }
    
    # Clear flag
    $script:IsRefreshingMgmt = $false
    
    Write-Host "✓ Management lists refreshed" -ForegroundColor Green
}

#endregion

#region Main Form

function Show-MainApplication {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "STIG Analysis Desktop Application"
    $form.Size = New-Object System.Drawing.Size(1400, 900)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::FromArgb(248, 249, 250)
    $form.MinimumSize = New-Object System.Drawing.Size(1200, 700)
    $form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    
    # Menu Bar
    $menuStrip = New-Object System.Windows.Forms.MenuStrip
    $menuStrip.BackColor = [System.Drawing.Color]::FromArgb(255, 255, 255)
    $menuStrip.Font = New-Object System.Drawing.Font("Segoe UI", 9)

    $fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&File")
    $importCciMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Import CCI Mappings...")
    $importStigMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Import STIG Files...")
    $exitMenu = New-Object System.Windows.Forms.ToolStripMenuItem("E&xit")

    [void]$fileMenu.DropDownItems.Add($importCciMenu)
    [void]$fileMenu.DropDownItems.Add($importStigMenu)
    [void]$fileMenu.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    [void]$fileMenu.DropDownItems.Add($exitMenu)
    [void]$menuStrip.Items.Add($fileMenu)

    $viewMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&View")
    $refreshMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Refresh")
    [void]$viewMenu.DropDownItems.Add($refreshMenu)
    [void]$menuStrip.Items.Add($viewMenu)

    $form.Controls.Add($menuStrip)
    
    # Application Banner
    $bannerPanel = New-Object System.Windows.Forms.Panel
    $bannerPanel.Location = New-Object System.Drawing.Point(0, 28)
    $bannerPanel.Size = New-Object System.Drawing.Size(1400, 70)
    $bannerPanel.BackColor = [System.Drawing.Color]::FromArgb(32, 99, 155)
    $bannerPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor
                          [System.Windows.Forms.AnchorStyles]::Left -bor
                          [System.Windows.Forms.AnchorStyles]::Right

    $bannerLabel = New-Object System.Windows.Forms.Label
    $bannerLabel.Text = "STIG Analysis Tool"
    $bannerLabel.Location = New-Object System.Drawing.Point(0, 0)
    $bannerLabel.Size = New-Object System.Drawing.Size(1400, 70)
    $bannerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $bannerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 20, [System.Drawing.FontStyle]::Bold)
    $bannerLabel.ForeColor = [System.Drawing.Color]::White
    $bannerLabel.BackColor = [System.Drawing.Color]::Transparent
    $bannerLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor
                          [System.Windows.Forms.AnchorStyles]::Left -bor
                          [System.Windows.Forms.AnchorStyles]::Right
    $bannerPanel.Controls.Add($bannerLabel)

    $form.Controls.Add($bannerPanel)
    
    # Tab Control
    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Location = New-Object System.Drawing.Point(10, 108)
    $tabControl.Size = New-Object System.Drawing.Size(1365, 730)
    $tabControl.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $tabControl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor
                         [System.Windows.Forms.AnchorStyles]::Bottom -bor
                         [System.Windows.Forms.AnchorStyles]::Left -bor
                         [System.Windows.Forms.AnchorStyles]::Right
    
    # Management Tab
    $managementTab = New-Object System.Windows.Forms.TabPage
    $managementTab.Text = "  Management  "
    $managementTab.BackColor = [System.Drawing.Color]::White
    
    $mgmtStatusBar = New-Object System.Windows.Forms.Panel
    $mgmtStatusBar.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $mgmtStatusBar.Height = 10
    $mgmtStatusBar.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    
    $mgmtStatusLabel = New-Object System.Windows.Forms.Label
    $mgmtStatusLabel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $mgmtStatusLabel.Text = "Ready"
    $mgmtStatusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
    $mgmtStatusLabel.Padding = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)
    $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Gray
    $mgmtStatusBar.Controls.Add($mgmtStatusLabel)
    
    $managementTab.Controls.Add($mgmtStatusBar)
    
    $mgmtSplitter = New-Object System.Windows.Forms.SplitContainer
    $mgmtSplitter.Dock = [System.Windows.Forms.DockStyle]::Fill
    $mgmtSplitter.SplitterWidth = 8
    $mgmtSplitter.BackColor = [System.Drawing.Color]::FromArgb(220, 220, 220)
    # Let it default to 50/50 split automatically without constraints
    
    # Sites Panel (Left)
    $sitesGroupBox = New-Object System.Windows.Forms.GroupBox
    $sitesGroupBox.Text = " Sites "
    $sitesGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $sitesGroupBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    $sitesGroupBox.Padding = New-Object System.Windows.Forms.Padding(15)
    $sitesGroupBox.ForeColor = [System.Drawing.Color]::FromArgb(64, 64, 64)
    
    $sitesListBox = New-Object System.Windows.Forms.ListBox
    $sitesListBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    $sitesListBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $sitesListBox.BackColor = [System.Drawing.Color]::White
    $sitesListBox.ForeColor = [System.Drawing.Color]::Black
    $sitesListBox.FormattingEnabled = $true
    $sitesListBox.DrawMode = [System.Windows.Forms.DrawMode]::Normal
    $sitesListBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $sitesListBox.ItemHeight = 20
    $sitesListBox.Add_DrawItem({
        param($sender, $e)
        if ($e.Index -ge 0) {
            $e.DrawBackground()
            $text = $sender.Items[$e.Index].ToString()
            $isSelected = ($e.State -band [System.Windows.Forms.DrawItemState]::Selected) -ne 0
            $textColor = if ($isSelected) { [System.Drawing.Color]::White } else { [System.Drawing.Color]::Black }
            $flags = [System.Windows.Forms.TextFormatFlags]::Left -bor [System.Windows.Forms.TextFormatFlags]::VerticalCenter
            [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $text, $sender.Font, $e.Bounds, $textColor, $flags)
            $e.DrawFocusRectangle()
        }
    })
    $sitesGroupBox.Controls.Add($sitesListBox)
    
    $sitesButtonPanel = New-Object System.Windows.Forms.Panel
    $sitesButtonPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $sitesButtonPanel.Height = 50
    $sitesButtonPanel.Padding = New-Object System.Windows.Forms.Padding(10, 5, 10, 5)
    
    $addSiteBtn = New-StyledButton -Text "+ Add Site" -Location (New-Object System.Drawing.Point(10, 8)) -Size (New-Object System.Drawing.Size(130, 38))
    $addSiteBtn.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
    $sitesButtonPanel.Controls.Add($addSiteBtn)

    $editSiteBtn = New-StyledButton -Text "Edit Site" -Location (New-Object System.Drawing.Point(150, 8)) -Size (New-Object System.Drawing.Size(130, 38))
    $editSiteBtn.BackColor = [System.Drawing.Color]::FromArgb(0, 123, 255)
    $sitesButtonPanel.Controls.Add($editSiteBtn)

    $deleteSiteBtn = New-StyledButton -Text "Delete Site" -Location (New-Object System.Drawing.Point(290, 8)) -Size (New-Object System.Drawing.Size(130, 38))
    $deleteSiteBtn.BackColor = [System.Drawing.Color]::FromArgb(220, 53, 69)
    $sitesButtonPanel.Controls.Add($deleteSiteBtn)
    
    $sitesGroupBox.Controls.Add($sitesButtonPanel)
    $mgmtSplitter.Panel1.Controls.Add($sitesGroupBox)
    
    # Systems Panel (Right)
    $systemsGroupBox = New-Object System.Windows.Forms.GroupBox
    $systemsGroupBox.Text = " Systems "
    $systemsGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $systemsGroupBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    $systemsGroupBox.Padding = New-Object System.Windows.Forms.Padding(15)
    $systemsGroupBox.ForeColor = [System.Drawing.Color]::FromArgb(64, 64, 64)
    
    $systemsListBox = New-Object System.Windows.Forms.ListBox
    $systemsListBox.Dock = [System.Windows.Forms.DockStyle]::Fill
    $systemsListBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $systemsListBox.BackColor = [System.Drawing.Color]::White
    $systemsListBox.ForeColor = [System.Drawing.Color]::Black
    $systemsListBox.FormattingEnabled = $true
    $systemsListBox.DrawMode = [System.Windows.Forms.DrawMode]::Normal
    $systemsListBox.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $systemsListBox.ItemHeight = 20
    $systemsListBox.Add_DrawItem({
        param($sender, $e)
        if ($e.Index -ge 0) {
            $e.DrawBackground()
            $text = $sender.Items[$e.Index].ToString()
            $isSelected = ($e.State -band [System.Windows.Forms.DrawItemState]::Selected) -ne 0
            $textColor = if ($isSelected) { [System.Drawing.Color]::White } else { [System.Drawing.Color]::Black }
            $flags = [System.Windows.Forms.TextFormatFlags]::Left -bor [System.Windows.Forms.TextFormatFlags]::VerticalCenter
            [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $text, $sender.Font, $e.Bounds, $textColor, $flags)
            $e.DrawFocusRectangle()
        }
    })
    $systemsGroupBox.Controls.Add($systemsListBox)
    
    $systemsButtonPanel = New-Object System.Windows.Forms.Panel
    $systemsButtonPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $systemsButtonPanel.Height = 50
    $systemsButtonPanel.Padding = New-Object System.Windows.Forms.Padding(10, 5, 10, 5)
    
    $addSystemBtn = New-StyledButton -Text "+ Add System" -Location (New-Object System.Drawing.Point(10, 8)) -Size (New-Object System.Drawing.Size(120, 35))
    $addSystemBtn.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $systemsButtonPanel.Controls.Add($addSystemBtn)
    
    $editSystemBtn = New-StyledButton -Text "Edit System" -Location (New-Object System.Drawing.Point(140, 8)) -Size (New-Object System.Drawing.Size(120, 35))
    $systemsButtonPanel.Controls.Add($editSystemBtn)
    
    $deleteSystemBtn = New-StyledButton -Text "Delete System" -Location (New-Object System.Drawing.Point(270, 8)) -Size (New-Object System.Drawing.Size(120, 35))
    $deleteSystemBtn.BackColor = [System.Drawing.Color]::FromArgb(200, 50, 50)
    $systemsButtonPanel.Controls.Add($deleteSystemBtn)
    
    $systemsGroupBox.Controls.Add($systemsButtonPanel)
    $mgmtSplitter.Panel2.Controls.Add($systemsGroupBox)
    
    $managementTab.Controls.Add($mgmtSplitter)
    $tabControl.Controls.Add($managementTab)
    
    # Dashboard Tab
    $dashboardTab = New-Object System.Windows.Forms.TabPage
    $dashboardTab.Text = "  Dashboard  "
    $dashboardTab.BackColor = [System.Drawing.Color]::WhiteSmoke
    $tabControl.Controls.Add($dashboardTab)
    
    # Browse Data Tab
    $browseTab = New-Object System.Windows.Forms.TabPage
    $browseTab.Text = "  Browse Data  "
    $browseTab.BackColor = [System.Drawing.Color]::White
    
    $browseToolbar = New-Object System.Windows.Forms.Panel
    $browseToolbar.Dock = [System.Windows.Forms.DockStyle]::Top
    $browseToolbar.Height = 80
    $browseToolbar.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
    
    # First row - Site/System filters
    $browseSiteLabel = New-Object System.Windows.Forms.Label
    $browseSiteLabel.Text = "Site:"
    $browseSiteLabel.Location = New-Object System.Drawing.Point(10, 15)
    $browseSiteLabel.Size = New-Object System.Drawing.Size(40, 20)
    $browseToolbar.Controls.Add($browseSiteLabel)
    
    $browseSiteComboBox = New-Object System.Windows.Forms.ComboBox
    $browseSiteComboBox.Location = New-Object System.Drawing.Point(55, 12)
    $browseSiteComboBox.Size = New-Object System.Drawing.Size(200, 25)
    $browseSiteComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $browseToolbar.Controls.Add($browseSiteComboBox)
    
    $browseSystemLabel = New-Object System.Windows.Forms.Label
    $browseSystemLabel.Text = "System:"
    $browseSystemLabel.Location = New-Object System.Drawing.Point(270, 15)
    $browseSystemLabel.Size = New-Object System.Drawing.Size(60, 20)
    $browseToolbar.Controls.Add($browseSystemLabel)
    
    $browseSystemComboBox = New-Object System.Windows.Forms.ComboBox
    $browseSystemComboBox.Location = New-Object System.Drawing.Point(335, 12)
    $browseSystemComboBox.Size = New-Object System.Drawing.Size(200, 25)
    $browseSystemComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $browseToolbar.Controls.Add($browseSystemComboBox)

    $browseSeverityLabel = New-Object System.Windows.Forms.Label
    $browseSeverityLabel.Text = "Severity:"
    $browseSeverityLabel.Location = New-Object System.Drawing.Point(550, 15)
    $browseSeverityLabel.Size = New-Object System.Drawing.Size(60, 20)
    $browseToolbar.Controls.Add($browseSeverityLabel)

    $browseSeverityComboBox = New-Object System.Windows.Forms.ComboBox
    $browseSeverityComboBox.Location = New-Object System.Drawing.Point(615, 12)
    $browseSeverityComboBox.Size = New-Object System.Drawing.Size(120, 25)
    $browseSeverityComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $browseSeverityComboBox.Items.AddRange(@("All", "critical", "high", "medium", "low"))
    $browseSeverityComboBox.SelectedIndex = 0
    $browseToolbar.Controls.Add($browseSeverityComboBox)

    $browseStatusLabel = New-Object System.Windows.Forms.Label
    $browseStatusLabel.Text = "Status:"
    $browseStatusLabel.Location = New-Object System.Drawing.Point(750, 15)
    $browseStatusLabel.Size = New-Object System.Drawing.Size(50, 20)
    $browseToolbar.Controls.Add($browseStatusLabel)

    $browseStatusComboBox = New-Object System.Windows.Forms.ComboBox
    $browseStatusComboBox.Location = New-Object System.Drawing.Point(805, 12)
    $browseStatusComboBox.Size = New-Object System.Drawing.Size(150, 25)
    $browseStatusComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $browseStatusComboBox.Items.AddRange(@("All", "Open", "NotAFinding", "Not_Reviewed", "Not_Applicable"))
    $browseStatusComboBox.SelectedIndex = 0
    $browseToolbar.Controls.Add($browseStatusComboBox)

    $browseRefreshBtn = New-StyledButton -Text "⟳" -Location (New-Object System.Drawing.Point(970, 10)) -Size (New-Object System.Drawing.Size(35, 28))
    $browseRefreshBtn.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $browseToolbar.Controls.Add($browseRefreshBtn)
    
    # Second row - Search and filters
    $refreshDataBtn = New-StyledButton -Text "Refresh All" -Location (New-Object System.Drawing.Point(10, 45)) -Size (New-Object System.Drawing.Size(100, 30))
    $browseToolbar.Controls.Add($refreshDataBtn)
    
    $searchLabel = New-Object System.Windows.Forms.Label
    $searchLabel.Text = "Search:"
    $searchLabel.Location = New-Object System.Drawing.Point(130, 50)
    $searchLabel.Size = New-Object System.Drawing.Size(60, 20)
    $browseToolbar.Controls.Add($searchLabel)
    
    $searchBox = New-Object System.Windows.Forms.TextBox
    $searchBox.Location = New-Object System.Drawing.Point(190, 47)
    $searchBox.Size = New-Object System.Drawing.Size(300, 25)
    $browseToolbar.Controls.Add($searchBox)
    
    $searchBtn = New-StyledButton -Text "Search" -Location (New-Object System.Drawing.Point(500, 45)) -Size (New-Object System.Drawing.Size(80, 30))
    $browseToolbar.Controls.Add($searchBtn)
    
    $clearFiltersBtn = New-StyledButton -Text "Clear Filters" -Location (New-Object System.Drawing.Point(590, 45)) -Size (New-Object System.Drawing.Size(100, 30))
    $clearFiltersBtn.BackColor = [System.Drawing.Color]::FromArgb(108, 117, 125)
    $browseToolbar.Controls.Add($clearFiltersBtn)
    
    $browseTab.Controls.Add($browseToolbar)
    
    $browseDataGrid = New-Object System.Windows.Forms.DataGridView
    $browseDataGrid.Location = New-Object System.Drawing.Point(0, 80)
    $browseDataGrid.Size = New-Object System.Drawing.Size(1175, 580)
    $browseDataGrid.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor 
                             [System.Windows.Forms.AnchorStyles]::Bottom -bor
                             [System.Windows.Forms.AnchorStyles]::Left -bor
                             [System.Windows.Forms.AnchorStyles]::Right
    $browseDataGrid.ReadOnly = $true
    $browseDataGrid.AllowUserToAddRows = $false
    $browseDataGrid.SelectionMode = 'FullRowSelect'
    $browseDataGrid.BackgroundColor = [System.Drawing.Color]::White
    $browseTab.Controls.Add($browseDataGrid)
    
    $browseStatusLabel = New-Object System.Windows.Forms.Label
    $browseStatusLabel.Location = New-Object System.Drawing.Point(10, 668)
    $browseStatusLabel.Size = New-Object System.Drawing.Size(1000, 20)
    $browseStatusLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
    $browseStatusLabel.Text = "Ready"
    $browseTab.Controls.Add($browseStatusLabel)
    
    $tabControl.Controls.Add($browseTab)
    
    # Import Tab
    $importTab = New-Object System.Windows.Forms.TabPage
    $importTab.Text = "  Import Data  "
    $importTab.BackColor = [System.Drawing.Color]::White
    
    # Import Context Selection Panel
    $importContextPanel = New-Object System.Windows.Forms.Panel
    $importContextPanel.Location = New-Object System.Drawing.Point(20, 20)
    $importContextPanel.Size = New-Object System.Drawing.Size(1140, 80)
    $importContextPanel.BackColor = [System.Drawing.Color]::FromArgb(248, 249, 250)
    $importContextPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    
    $importContextLabel = New-Object System.Windows.Forms.Label
    $importContextLabel.Text = "Select Site and System for Import:"
    $importContextLabel.Location = New-Object System.Drawing.Point(15, 15)
    $importContextLabel.Size = New-Object System.Drawing.Size(200, 20)
    $importContextLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $importContextLabel.ForeColor = [System.Drawing.Color]::FromArgb(64, 64, 64)
    $importContextPanel.Controls.Add($importContextLabel)
    
    $importSiteLabel = New-Object System.Windows.Forms.Label
    $importSiteLabel.Text = "Site:"
    $importSiteLabel.Location = New-Object System.Drawing.Point(15, 45)
    $importSiteLabel.Size = New-Object System.Drawing.Size(40, 20)
    $importSiteLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $importContextPanel.Controls.Add($importSiteLabel)
    
    $importSiteComboBox = New-Object System.Windows.Forms.ComboBox
    $importSiteComboBox.Location = New-Object System.Drawing.Point(60, 42)
    $importSiteComboBox.Size = New-Object System.Drawing.Size(250, 25)
    $importSiteComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $importContextPanel.Controls.Add($importSiteComboBox)
    
    $importSystemLabel = New-Object System.Windows.Forms.Label
    $importSystemLabel.Text = "System:"
    $importSystemLabel.Location = New-Object System.Drawing.Point(330, 45)
    $importSystemLabel.Size = New-Object System.Drawing.Size(60, 20)
    $importSystemLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $importContextPanel.Controls.Add($importSystemLabel)
    
    $importSystemComboBox = New-Object System.Windows.Forms.ComboBox
    $importSystemComboBox.Location = New-Object System.Drawing.Point(395, 42)
    $importSystemComboBox.Size = New-Object System.Drawing.Size(250, 25)
    $importSystemComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $importContextPanel.Controls.Add($importSystemComboBox)
    
    $importRefreshBtn = New-StyledButton -Text "⟳" -Location (New-Object System.Drawing.Point(655, 40)) -Size (New-Object System.Drawing.Size(35, 28))
    $importRefreshBtn.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $importContextPanel.Controls.Add($importRefreshBtn)
    
    $importTab.Controls.Add($importContextPanel)
    
    # Import Actions Panel
    $importActionsPanel = New-Object System.Windows.Forms.Panel
    $importActionsPanel.Location = New-Object System.Drawing.Point(20, 120)
    $importActionsPanel.Size = New-Object System.Drawing.Size(1140, 520)
    
    $stigGroupBox = New-Object System.Windows.Forms.GroupBox
    $stigGroupBox.Location = New-Object System.Drawing.Point(0, 0)
    $stigGroupBox.Size = New-Object System.Drawing.Size(1140, 250)
    $stigGroupBox.Text = " Import STIG Files (CKL/CKLB) "
    $stigGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $stigGroupBox.ForeColor = [System.Drawing.Color]::FromArgb(64, 64, 64)
    
    $importStigBtn = New-StyledButton -Text "Import STIG Files..." -Location (New-Object System.Drawing.Point(20, 30)) -Size (New-Object System.Drawing.Size(200, 40))
    $importStigBtn.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
    $stigGroupBox.Controls.Add($importStigBtn)
    
    $stigStatusLabel = New-Object System.Windows.Forms.Label
    $stigStatusLabel.Location = New-Object System.Drawing.Point(240, 35)
    $stigStatusLabel.Size = New-Object System.Drawing.Size(880, 20)
    $stigStatusLabel.Text = "No STIG files loaded - Select site and system first"
    $stigStatusLabel.ForeColor = [System.Drawing.Color]::Gray
    $stigGroupBox.Controls.Add($stigStatusLabel)
    
    # File Upload Progress Section
    $fileUploadLabel = New-Object System.Windows.Forms.Label
    $fileUploadLabel.Text = "File Upload Progress:"
    $fileUploadLabel.Location = New-Object System.Drawing.Point(20, 85)
    $fileUploadLabel.Size = New-Object System.Drawing.Size(150, 20)
    $fileUploadLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $stigGroupBox.Controls.Add($fileUploadLabel)
    
    $stigFileUploadProgressBar = New-Object System.Windows.Forms.ProgressBar
    $stigFileUploadProgressBar.Location = New-Object System.Drawing.Point(20, 105)
    $stigFileUploadProgressBar.Size = New-Object System.Drawing.Size(1100, 20)
    $stigFileUploadProgressBar.Visible = $false
    $stigGroupBox.Controls.Add($stigFileUploadProgressBar)
    
    $stigFileUploadDetailLabel = New-Object System.Windows.Forms.Label
    $stigFileUploadDetailLabel.Text = ""
    $stigFileUploadDetailLabel.Location = New-Object System.Drawing.Point(20, 130)
    $stigFileUploadDetailLabel.Size = New-Object System.Drawing.Size(1100, 15)
    $stigFileUploadDetailLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $stigFileUploadDetailLabel.ForeColor = [System.Drawing.Color]::DarkBlue
    $stigGroupBox.Controls.Add($stigFileUploadDetailLabel)
    
    # Processing Progress Section
    $processingLabel = New-Object System.Windows.Forms.Label
    $processingLabel.Text = "Processing Progress:"
    $processingLabel.Location = New-Object System.Drawing.Point(20, 155)
    $processingLabel.Size = New-Object System.Drawing.Size(150, 20)
    $processingLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $stigGroupBox.Controls.Add($processingLabel)
    
    $stigProcessingProgressBar = New-Object System.Windows.Forms.ProgressBar
    $stigProcessingProgressBar.Location = New-Object System.Drawing.Point(20, 175)
    $stigProcessingProgressBar.Size = New-Object System.Drawing.Size(1100, 20)
    $stigProcessingProgressBar.Visible = $false
    $stigGroupBox.Controls.Add($stigProcessingProgressBar)
    
    $stigProcessingDetailLabel = New-Object System.Windows.Forms.Label
    $stigProcessingDetailLabel.Text = ""
    $stigProcessingDetailLabel.Location = New-Object System.Drawing.Point(20, 200)
    $stigProcessingDetailLabel.Size = New-Object System.Drawing.Size(1100, 15)
    $stigProcessingDetailLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $stigProcessingDetailLabel.ForeColor = [System.Drawing.Color]::DarkGreen
    $stigGroupBox.Controls.Add($stigProcessingDetailLabel)
    
    # Overall progress bar
    $stigOverallProgressBar = New-Object System.Windows.Forms.ProgressBar
    $stigOverallProgressBar.Location = New-Object System.Drawing.Point(240, 60)
    $stigOverallProgressBar.Size = New-Object System.Drawing.Size(880, 23)
    $stigOverallProgressBar.Visible = $false
    $stigGroupBox.Controls.Add($stigOverallProgressBar)
    
    $stigOverallDetailLabel = New-Object System.Windows.Forms.Label
    $stigOverallDetailLabel.Location = New-Object System.Drawing.Point(240, 85)
    $stigOverallDetailLabel.Size = New-Object System.Drawing.Size(880, 15)
    $stigOverallDetailLabel.Text = ""
    $stigOverallDetailLabel.ForeColor = [System.Drawing.Color]::DarkBlue
    $stigOverallDetailLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $stigGroupBox.Controls.Add($stigOverallDetailLabel)
    
    # Current file progress
    $stigCurrentFileLabel = New-Object System.Windows.Forms.Label
    $stigCurrentFileLabel.Location = New-Object System.Drawing.Point(240, 105)
    $stigCurrentFileLabel.Size = New-Object System.Drawing.Size(880, 15)
    $stigCurrentFileLabel.Text = ""
    $stigCurrentFileLabel.ForeColor = [System.Drawing.Color]::DarkGreen
    $stigCurrentFileLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $stigGroupBox.Controls.Add($stigCurrentFileLabel)
    
    $stigCurrentProgressBar = New-Object System.Windows.Forms.ProgressBar
    $stigCurrentProgressBar.Location = New-Object System.Drawing.Point(240, 125)
    $stigCurrentProgressBar.Size = New-Object System.Drawing.Size(880, 20)
    $stigCurrentProgressBar.Visible = $false
    $stigGroupBox.Controls.Add($stigCurrentProgressBar)
    
    $stigCurrentDetailLabel = New-Object System.Windows.Forms.Label
    $stigCurrentDetailLabel.Location = New-Object System.Drawing.Point(240, 150)
    $stigCurrentDetailLabel.Size = New-Object System.Drawing.Size(880, 15)
    $stigCurrentDetailLabel.Text = ""
    $stigCurrentDetailLabel.ForeColor = [System.Drawing.Color]::DarkBlue
    $stigCurrentDetailLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $stigGroupBox.Controls.Add($stigCurrentDetailLabel)
    
    $stigSummaryDetailLabel = New-Object System.Windows.Forms.Label
    $stigSummaryDetailLabel.Location = New-Object System.Drawing.Point(240, 170)
    $stigSummaryDetailLabel.Size = New-Object System.Drawing.Size(880, 15)
    $stigSummaryDetailLabel.Text = ""
    $stigSummaryDetailLabel.ForeColor = [System.Drawing.Color]::Purple
    $stigSummaryDetailLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
    $stigGroupBox.Controls.Add($stigSummaryDetailLabel)
    
    $importActionsPanel.Controls.Add($stigGroupBox)
    
    # CCI Processing GroupBox
    $cciProcessingGroupBox = New-Object System.Windows.Forms.GroupBox
    $cciProcessingGroupBox.Text = " CCI Mapping Processing "
    $cciProcessingGroupBox.Location = New-Object System.Drawing.Point(0, 270)
    $cciProcessingGroupBox.Size = New-Object System.Drawing.Size(1140, 80)
    $cciProcessingGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $cciProcessingGroupBox.ForeColor = [System.Drawing.Color]::FromArgb(64, 64, 64)
    
    $cciProcessingLabel = New-Object System.Windows.Forms.Label
    $cciProcessingLabel.Text = "CCI mappings will be processed automatically during STIG import"
    $cciProcessingLabel.Location = New-Object System.Drawing.Point(20, 30)
    $cciProcessingLabel.Size = New-Object System.Drawing.Size(1100, 20)
    $cciProcessingLabel.ForeColor = [System.Drawing.Color]::DarkBlue
    $cciProcessingGroupBox.Controls.Add($cciProcessingLabel)
    
    $cciProcessingProgressBar = New-Object System.Windows.Forms.ProgressBar
    $cciProcessingProgressBar.Location = New-Object System.Drawing.Point(20, 55)
    $cciProcessingProgressBar.Size = New-Object System.Drawing.Size(1100, 15)
    $cciProcessingProgressBar.Visible = $false
    $cciProcessingGroupBox.Controls.Add($cciProcessingProgressBar)
    
    $importActionsPanel.Controls.Add($cciProcessingGroupBox)
    
    # Import Summary Panel
    $importSummaryGroupBox = New-Object System.Windows.Forms.GroupBox
    $importSummaryGroupBox.Location = New-Object System.Drawing.Point(0, 360)
    $importSummaryGroupBox.Size = New-Object System.Drawing.Size(1140, 140)
    $importSummaryGroupBox.Text = " Import Summary "
    $importSummaryGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $importSummaryGroupBox.ForeColor = [System.Drawing.Color]::FromArgb(64, 64, 64)
    
    $importSummaryLabel = New-Object System.Windows.Forms.Label
    $importSummaryLabel.Location = New-Object System.Drawing.Point(20, 30)
    $importSummaryLabel.Size = New-Object System.Drawing.Size(1100, 80)
    $importSummaryLabel.Text = "Select a site and system above to begin importing data. All imported STIG files will be associated with the selected system."
    $importSummaryLabel.ForeColor = [System.Drawing.Color]::FromArgb(96, 96, 96)
    $importSummaryLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $importSummaryGroupBox.Controls.Add($importSummaryLabel)
    
    $importActionsPanel.Controls.Add($importSummaryGroupBox)
    
    $importTab.Controls.Add($importActionsPanel)
    $tabControl.Controls.Add($importTab)
    
    # CCI Management Tab
    $cciManagementTab = New-Object System.Windows.Forms.TabPage
    $cciManagementTab.Text = "  CCI Management  "
    $cciManagementTab.BackColor = [System.Drawing.Color]::White
    
    # CCI Management Panel
    $cciMgmtPanel = New-Object System.Windows.Forms.Panel
    $cciMgmtPanel.Location = New-Object System.Drawing.Point(10, 10)
    $cciMgmtPanel.Size = New-Object System.Drawing.Size(1150, 620)
    $cciMgmtPanel.BackColor = [System.Drawing.Color]::White
    $cciManagementTab.Controls.Add($cciMgmtPanel)
    
    # CCI Status Group
    $cciStatusGroup = New-Object System.Windows.Forms.GroupBox
    $cciStatusGroup.Text = "Current CCI Data Status"
    $cciStatusGroup.Location = New-Object System.Drawing.Point(10, 10)
    $cciStatusGroup.Size = New-Object System.Drawing.Size(1130, 120)
    $cciMgmtPanel.Controls.Add($cciStatusGroup)
    
    # CCI Status Label
    $cciStatusLabel = New-Object System.Windows.Forms.Label
    $cciStatusLabel.Text = "No CCI data loaded"
    $cciStatusLabel.Location = New-Object System.Drawing.Point(20, 30)
    $cciStatusLabel.Size = New-Object System.Drawing.Size(1090, 60)
    $cciStatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $cciStatusGroup.Controls.Add($cciStatusLabel)
    
    # CCI Actions Group
    $cciActionsGroup = New-Object System.Windows.Forms.GroupBox
    $cciActionsGroup.Text = "CCI Data Management"
    $cciActionsGroup.Location = New-Object System.Drawing.Point(10, 140)
    $cciActionsGroup.Size = New-Object System.Drawing.Size(1130, 200)
    $cciMgmtPanel.Controls.Add($cciActionsGroup)
    
    # Import CCI Button
    $importCciMgmtBtn = New-Object System.Windows.Forms.Button
    $importCciMgmtBtn.Text = "Import CCI Mappings"
    $importCciMgmtBtn.Location = New-Object System.Drawing.Point(20, 40)
    $importCciMgmtBtn.Size = New-Object System.Drawing.Size(200, 40)
    $importCciMgmtBtn.BackColor = [System.Drawing.Color]::LightBlue
    $importCciMgmtBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $cciActionsGroup.Controls.Add($importCciMgmtBtn)
    
    # Clear CCI Button
    $clearCciBtn = New-Object System.Windows.Forms.Button
    $clearCciBtn.Text = "Clear CCI Data"
    $clearCciBtn.Location = New-Object System.Drawing.Point(240, 40)
    $clearCciBtn.Size = New-Object System.Drawing.Size(150, 40)
    $clearCciBtn.BackColor = [System.Drawing.Color]::LightCoral
    $clearCciBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $cciActionsGroup.Controls.Add($clearCciBtn)
    
    # Refresh Status Button
    $refreshCciStatusBtn = New-Object System.Windows.Forms.Button
    $refreshCciStatusBtn.Text = "Refresh Status"
    $refreshCciStatusBtn.Location = New-Object System.Drawing.Point(410, 40)
    $refreshCciStatusBtn.Size = New-Object System.Drawing.Size(150, 40)
    $refreshCciStatusBtn.BackColor = [System.Drawing.Color]::LightGreen
    $refreshCciStatusBtn.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $cciActionsGroup.Controls.Add($refreshCciStatusBtn)
    
    # CCI Progress Bar
    $cciMgmtProgressBar = New-Object System.Windows.Forms.ProgressBar
    $cciMgmtProgressBar.Location = New-Object System.Drawing.Point(20, 100)
    $cciMgmtProgressBar.Size = New-Object System.Drawing.Size(1090, 25)
    $cciMgmtProgressBar.Visible = $false
    $cciActionsGroup.Controls.Add($cciMgmtProgressBar)
    
    # CCI Progress Label
    $cciMgmtProgressLabel = New-Object System.Windows.Forms.Label
    $cciMgmtProgressLabel.Text = ""
    $cciMgmtProgressLabel.Location = New-Object System.Drawing.Point(20, 135)
    $cciMgmtProgressLabel.Size = New-Object System.Drawing.Size(1090, 40)
    $cciMgmtProgressLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $cciMgmtProgressLabel.ForeColor = [System.Drawing.Color]::DarkBlue
    $cciActionsGroup.Controls.Add($cciMgmtProgressLabel)
    
    # CCI Data Preview Group
    $cciPreviewGroup = New-Object System.Windows.Forms.GroupBox
    $cciPreviewGroup.Text = "CCI Data Preview"
    $cciPreviewGroup.Location = New-Object System.Drawing.Point(10, 350)
    $cciPreviewGroup.Size = New-Object System.Drawing.Size(1130, 260)
    $cciMgmtPanel.Controls.Add($cciPreviewGroup)
    
    # CCI Data Grid
    $cciDataGrid = New-Object System.Windows.Forms.DataGridView
    $cciDataGrid.Location = New-Object System.Drawing.Point(10, 25)
    $cciDataGrid.Size = New-Object System.Drawing.Size(1110, 225)
    $cciDataGrid.AllowUserToAddRows = $false
    $cciDataGrid.AllowUserToDeleteRows = $false
    $cciDataGrid.ReadOnly = $true
    $cciDataGrid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $cciDataGrid.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
    $cciDataGrid.BackgroundColor = [System.Drawing.Color]::White
    $cciPreviewGroup.Controls.Add($cciDataGrid)
    
    $tabControl.Controls.Add($cciManagementTab)
    
    $form.Controls.Add($tabControl)
    
    # TabControl Event - Auto-refresh management lists when tab is selected
    $tabControl.Add_SelectedIndexChanged({
        try {
            Write-Host "Debug: Tab changed to: $($tabControl.SelectedTab.Text)" -ForegroundColor DarkGray
            if ($tabControl.SelectedTab -eq $managementTab) {
                Write-Host "Debug: Management tab selected, refreshing lists..." -ForegroundColor DarkGray
                if ($sitesListBox -and $systemsListBox) {
                    Refresh-ManagementLists -SitesListBox $sitesListBox -SystemsListBox $systemsListBox
                }
                else {
                    Write-Host "Debug: Missing listboxes for management refresh" -ForegroundColor Red
                }
            }
            elseif ($tabControl.SelectedTab -eq $browseTab) {
                Write-Host "Debug: Browse Data tab selected, loading data..." -ForegroundColor DarkGray
                if ($browseDataGrid -and $browseStatusLabel) {
                    Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox
                }
                else {
                    Write-Host "Debug: Missing controls for browse data refresh" -ForegroundColor Red
                }
            }
            elseif ($tabControl.SelectedTab -eq $cciManagementTab) {
                Write-Host "Debug: CCI Management tab selected, refreshing status..." -ForegroundColor DarkGray
                Update-CciStatus -StatusLabel $cciStatusLabel -DataGrid $cciDataGrid
            }
        }
        catch {
            Write-Host "  Error refreshing management lists: $($_.Exception.Message)" -ForegroundColor Red
        }
    })
    
    # Status Bar
    $statusBar = New-Object System.Windows.Forms.StatusStrip
    $statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusLabel.Text = "Ready | Database: $script:DatabasePath"
    [void]$statusBar.Items.Add($statusLabel)
    $form.Controls.Add($statusBar)
    
    # Event Handlers
    # CCI import handler removed - now handled in CCI Management tab
    
    # CCI import moved to CCI Management tab
    
    # Import Context Event Handlers
    $importSiteComboBox.Add_SelectedIndexChanged({
        # Refresh systems when site changes
        $importSystemComboBox.DataSource = $null
        $selectedSiteId = if ($importSiteComboBox.SelectedValue) { [int]$importSiteComboBox.SelectedValue } else { 0 }
        if ($selectedSiteId -gt 0) {
            $systems = Get-Systems -SiteId $selectedSiteId
            if ($systems -and $systems.Rows.Count -gt 0) {
                $sysItems = New-Object System.Collections.ArrayList
                foreach ($row in $systems.Rows) {
                    $name = if ($row.System_Name -is [DBNull]) { '' } else { $row.System_Name.ToString() }
                    $null = $sysItems.Add([pscustomobject]@{ System_ID = [int]$row.System_ID; DisplayName = $name })
                }
                $importSystemComboBox.DisplayMember = 'DisplayName'
                $importSystemComboBox.ValueMember = 'System_ID'
                $importSystemComboBox.DataSource = $sysItems
                if ($importSystemComboBox.Items.Count -gt 0) {
                    $importSystemComboBox.SelectedIndex = 0
                }
            }
        }
        
        # Update status labels
        Update-ImportStatus -CciStatusLabel $cciStatusLabel -StigStatusLabel $stigStatusLabel -ImportSiteCombo $importSiteComboBox -ImportSystemCombo $importSystemComboBox
    })
    
    $importSystemComboBox.Add_SelectedIndexChanged({
        # Update status labels when system changes
        Update-ImportStatus -CciStatusLabel $cciStatusLabel -StigStatusLabel $stigStatusLabel -ImportSiteCombo $importSiteComboBox -ImportSystemCombo $importSystemComboBox
    })
    
    $importRefreshBtn.Add_Click({
        Refresh-ImportContextSelectors -ImportSiteCombo $importSiteComboBox -ImportSystemCombo $importSystemComboBox
    })
    
    $importStigHandler = {
        # Check if system is selected in import context
        if (-not $importSystemComboBox.SelectedItem) {
            [System.Windows.Forms.MessageBox]::Show("Please select a Site and System in the Import Data tab first.", "Information", "OK", "Information")
            return
        }
        
        $systemId = [int]$importSystemComboBox.SelectedValue
        
        # Check if CCI mappings exist
        $cciCount = $script:DatabaseConnection.ExecuteQuery("SELECT COUNT(*) AS cnt FROM CCI_Mappings")
        if ($cciCount.Rows[0].cnt -eq 0) {
            $result = [System.Windows.Forms.MessageBox]::Show("No CCI mappings found. Please import CCI mappings from the CCI Management tab first, or import them now from the Import Data tab.", "CCI Mappings Required", "OKCancel", "Information")
            if ($result -eq "Cancel") {
            return
            }
        }
        
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Filter = "STIG Files (*.ckl;*.cklb)|*.ckl;*.cklb"
        $openFileDialog.Title = "Select STIG Files"
        $openFileDialog.Multiselect = $true
        
        if ($openFileDialog.ShowDialog() -eq "OK") {
            # Show file upload progress
            $stigFileUploadProgressBar.Visible = $true
            $stigFileUploadProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
            $stigFileUploadProgressBar.Maximum = $openFileDialog.FileNames.Count
            $stigFileUploadProgressBar.Value = 0
            
            # Show processing progress
            $stigProcessingProgressBar.Visible = $true
            $stigProcessingProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
            $stigProcessingProgressBar.Maximum = $openFileDialog.FileNames.Count
            $stigProcessingProgressBar.Value = 0
            
            $stigFileUploadDetailLabel.Text = "Preparing to read $($openFileDialog.FileNames.Count) STIG files..."
            $stigProcessingDetailLabel.Text = "Preparing to process files..."
            $stigSummaryDetailLabel.Text = "Files imported: 0 | Total findings: 0 | Skipped: 0 | Overwritten: 0"
            $importTab.Refresh()
            
            $stigStatusLabel.Text = "Importing..."
            $stigStatusLabel.Refresh()
            
            $totalImported = 0
            $totalVulns = 0
            $totalSkipped = 0
            $totalOverwritten = 0
            
            try {
                for ($i = 0; $i -lt $openFileDialog.FileNames.Count; $i++) {
                    $file = $openFileDialog.FileNames[$i]
                $fileName = Split-Path -Path $file -Leaf
                $extension = [System.IO.Path]::GetExtension($file).ToLower()
                
                    # Show file reading progress
                    $stigFileUploadProgressBar.Value = $i + 1
                    $stigFileUploadDetailLabel.Text = "Reading file $($i + 1) of $($openFileDialog.FileNames.Count): $fileName"
                    $importTab.Refresh()
                    
                    # Get file size for progress tracking
                    $fileInfo = Get-Item $file
                    $fileSizeKB = [math]::Round($fileInfo.Length / 1KB, 1)
                    $stigFileUploadDetailLabel.Text = "Read file $($i + 1) of $($openFileDialog.FileNames.Count): $fileName ($fileSizeKB KB)"
                    $importTab.Refresh()
                
                    # Update processing display
                    $stigProcessingDetailLabel.Text = "Starting import of: $fileName"
                    $importTab.Refresh()
                    
                    # Check if already imported for this system
                    $existing = $script:DatabaseConnection.ExecuteQuery("SELECT File_ID FROM STIG_Files WHERE File_Name = '$fileName' AND System_ID = $systemId")
                    
                    if ($existing.Rows.Count -gt 0) {
                        $existingFileId = $existing.Rows[0].File_ID
                        $stigProcessingDetailLabel.Text = "File already exists - checking overwrite option"
                        $importTab.Refresh()
                        
                        # Ask user if they want to overwrite
                        $overwriteResult = [System.Windows.Forms.MessageBox]::Show(
                            "File '$fileName' already exists for this system.`n`nThis is common when remediating issues and importing updated scan results.`n`nDo you want to overwrite the existing file with the new data?",
                            "File Already Exists",
                            "YesNo",
                            "Question"
                        )
                        
                        if ($overwriteResult -eq "Yes") {
                            $stigCurrentDetailLabel.Text = "Overwriting existing file..."
                            $importTab.Refresh()
                            
                            # Delete existing vulnerabilities for this file
                            $script:DatabaseConnection.ExecuteNonQuery("DELETE FROM Vulnerabilities WHERE File_ID = $existingFileId") | Out-Null
                            
                            # Delete the existing file record
                            $script:DatabaseConnection.ExecuteNonQuery("DELETE FROM STIG_Files WHERE File_ID = $existingFileId") | Out-Null
                            
                            Write-Host "Overwriting existing file: $fileName" -ForegroundColor Yellow
                            $totalOverwritten++
                            $stigProcessingDetailLabel.Text = "Overwriting existing file: $fileName"
                            $importTab.Refresh()
                        } else {
                            $stigProcessingDetailLabel.Text = "File skipped by user choice"
                            $totalSkipped++
                            $stigProcessingProgressBar.Value = $i + 1
                            $stigProcessingDetailLabel.Text = "Processed $($i + 1) of $($openFileDialog.FileNames.Count) files"
                            $stigSummaryDetailLabel.Text = "Files imported: $totalImported | Total findings: $totalVulns | Skipped: $totalSkipped | Overwritten: $totalOverwritten"
                            $importTab.Refresh()
                            continue
                        }
                    }
                    
                    $stigProcessingDetailLabel.Text = "Extracting STIG information from: $fileName"
                    $importTab.Refresh()
                    
                    $stigTitle = ""
                if ($extension -eq '.ckl') {
                    [xml]$ckl = Get-Content -Path $file -Raw
                    $stigTitle = $ckl.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA | 
                        Where-Object { $_.SID_NAME -eq 'title' } | 
                        Select-Object -ExpandProperty SID_DATA
                }
                elseif ($extension -eq '.cklb') {
                    $json = Get-Content -Path $file -Raw | ConvertFrom-Json
                    $stigTitle = $json.title
                }
                    
                    $stigProcessingDetailLabel.Text = "Creating database record for: $fileName"
                    $importTab.Refresh()
                
                $stigTitleEsc = $stigTitle -replace "'", "''"
                
                    # Insert STIG file record
                    $script:DatabaseConnection.ExecuteNonQuery(@"
INSERT INTO STIG_Files (System_ID, File_Name, STIG_Title, Import_Date, Record_Count)
VALUES ($systemId, '$fileName', '$stigTitleEsc', NOW(), 0)
"@) | Out-Null
                    
                    $fileIdResult = $script:DatabaseConnection.ExecuteQuery("SELECT @@IDENTITY AS FileID")
                    $fileId = $fileIdResult.Rows[0].FileID
                    
                    $stigProcessingDetailLabel.Text = "Importing vulnerabilities from: $fileName"
                    $importTab.Refresh()
                    
                    # Import vulnerabilities
                    if ($extension -eq '.ckl') {
                        $result = Import-CklFile -Path $file -FileId $fileId
                    }
                    else {
                        $result = Import-CklbFile -Path $file -FileId $fileId
                    }
                    
                    if ($result.Success) {
                        # Update record count
                        $script:DatabaseConnection.ExecuteNonQuery("UPDATE STIG_Files SET Record_Count = $($result.Count) WHERE File_ID = $fileId") | Out-Null
                        $totalImported++
                        $totalVulns += $result.Count
                        $stigProcessingDetailLabel.Text = "Successfully imported $($result.Count) findings from: $fileName"
                    }
                    else {
                        $stigProcessingDetailLabel.Text = "Import failed: $($result.Error)"
                        $stigProcessingDetailLabel.ForeColor = [System.Drawing.Color]::Red
                    }
                    
                    # Show CCI processing progress
                    if ($result.Success -and $result.Count -gt 0) {
                        $cciProcessingProgressBar.Visible = $true
                        $cciProcessingProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
                        $cciProcessingProgressBar.Maximum = $result.Count
                        $cciProcessingProgressBar.Value = 0
                        $cciProcessingLabel.Text = "Processing CCI mappings for $($result.Count) findings..."
                        $importTab.Refresh()
                        
                        # Simulate CCI processing progress (since we can't easily hook into the actual processing)
                        for ($j = 1; $j -le $result.Count; $j++) {
                            $cciProcessingProgressBar.Value = $j
                            $cciProcessingLabel.Text = "Processing CCI mapping $j of $($result.Count) findings..."
                            $importTab.Refresh()
                            Start-Sleep -Milliseconds 10  # Small delay to show progress
                        }
                        
                        $cciProcessingLabel.Text = "CCI mapping processing completed for $($result.Count) findings"
                        $importTab.Refresh()
                        Start-Sleep -Milliseconds 500  # Brief pause to show completion
                        $cciProcessingProgressBar.Visible = $false
                    }
                    
                    # Update processing progress
                    $stigProcessingProgressBar.Value = $i + 1
                    $stigProcessingDetailLabel.Text = "Processed $($i + 1) of $($openFileDialog.FileNames.Count) files"
                    $stigSummaryDetailLabel.Text = "Files imported: $totalImported | Total findings: $totalVulns | Skipped: $totalSkipped | Overwritten: $totalOverwritten"
                    $importTab.Refresh()
                    
                    # Small delay to show progress
                    Start-Sleep -Milliseconds 100
                }
                
                # Hide progress bars
                $stigFileUploadProgressBar.Visible = $false
                $stigProcessingProgressBar.Visible = $false
            
            if ($totalImported -gt 0) {
                    $statusText = "Imported $totalImported files with $totalVulns findings"
                    if ($totalOverwritten -gt 0) {
                        $statusText += " (overwrote $totalOverwritten)"
                    }
                    $stigStatusLabel.Text = $statusText
                $stigStatusLabel.ForeColor = [System.Drawing.Color]::Green
                    
                    $stigProcessingDetailLabel.Text = "Import completed successfully"
                    $stigProcessingDetailLabel.ForeColor = [System.Drawing.Color]::Green
                    $stigCurrentFileLabel.Text = ""
                    $stigCurrentDetailLabel.Text = ""
                    
                    $messageText = "Successfully imported $totalImported STIG files with $totalVulns total findings!"
                    if ($totalOverwritten -gt 0) {
                        $messageText += "`nOverwrote $totalOverwritten existing files with new data."
                    }
                    if ($totalSkipped -gt 0) {
                        $messageText += "`nSkipped $totalSkipped files."
                    }
                    [System.Windows.Forms.MessageBox]::Show($messageText, "Success", "OK", "Information")
                
                # Refresh dashboard
                Refresh-Dashboard -DashboardTab $dashboardTab
            }
            else {
                    $stigStatusLabel.Text = "No files imported"
                $stigStatusLabel.ForeColor = [System.Drawing.Color]::Gray
                    
                    $stigProcessingDetailLabel.Text = "No files were imported"
                    $stigProcessingDetailLabel.ForeColor = [System.Drawing.Color]::Gray
                    $stigCurrentFileLabel.Text = ""
                    $stigCurrentDetailLabel.Text = ""
                    
                    $messageText = "No files were imported."
                    if ($totalSkipped -gt 0) {
                        $messageText += "`nSkipped $totalSkipped files."
                    }
                    [System.Windows.Forms.MessageBox]::Show($messageText, "Information", "OK", "Information")
                }
            }
            catch {
                # Hide progress bars
                $stigFileUploadProgressBar.Visible = $false
                $stigProcessingProgressBar.Visible = $false
                
                $stigStatusLabel.Text = "Import failed"
                $stigStatusLabel.ForeColor = [System.Drawing.Color]::Red
                $stigProcessingDetailLabel.Text = "Error: $($_.Exception.Message)"
                $stigProcessingDetailLabel.ForeColor = [System.Drawing.Color]::Red
                $stigCurrentFileLabel.Text = ""
                $stigCurrentDetailLabel.Text = ""
                
                [System.Windows.Forms.MessageBox]::Show("Import failed: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        }
    }
    
    $importStigBtn.Add_Click($importStigHandler)
    $importStigMenu.Add_Click($importStigHandler)
    
    $refreshDataBtn.Add_Click({
        Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox
    })
    
    $searchBtn.Add_Click({
        $searchTerm = $searchBox.Text
        if ([string]::IsNullOrWhiteSpace($searchTerm)) {
            Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox
            return
        }
        
        try {
            $browseStatusLabel.Text = "Searching..."
            $browseStatusLabel.Refresh()
            
            $searchTermEsc = $searchTerm -replace "'", "''"
            $data = $script:DatabaseConnection.ExecuteQuery(@"
SELECT 
    v.Group_ID AS [Vuln ID],
    v.Rule_ID AS [Rule ID],
    v.Rule_Title AS [Title],
    v.Severity,
    v.Status,
    v.NIST_Controls AS [NIST Controls],
    v.Control_Families AS [Families],
    v.CCI_References AS [CCIs],
    v.STIG_Name AS [STIG Name],
    s.File_Name AS [Source File]
FROM Vulnerabilities v
LEFT JOIN STIG_Files s ON v.File_ID = s.File_ID
WHERE 
    v.Rule_Title LIKE '%$searchTermEsc%' OR
    v.NIST_Controls LIKE '%$searchTermEsc%' OR
    v.Control_Families LIKE '%$searchTermEsc%' OR
    v.Group_ID LIKE '%$searchTermEsc%' OR
    v.Rule_ID LIKE '%$searchTermEsc%' OR
    v.CCI_References LIKE '%$searchTermEsc%'
ORDER BY v.Severity DESC
"@)
            
            $browseDataGrid.DataSource = $data
            $browseStatusLabel.Text = "Found $($data.Rows.Count) results"
            $browseStatusLabel.ForeColor = [System.Drawing.Color]::Green
        }
        catch {
            $browseStatusLabel.Text = "Search error: $($_.Exception.Message)"
            $browseStatusLabel.ForeColor = [System.Drawing.Color]::Red
        }
    })
    
    $refreshMenu.Add_Click({
        Refresh-Dashboard -DashboardTab $dashboardTab
        if ($tabControl.SelectedTab -eq $browseTab) {
            Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox
        }
    })
    
    # Browse Data Event Handlers
    $browseRefreshBtn.Add_Click({
        Refresh-BrowseFilters -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox
    })
    
    $browseSiteComboBox.Add_SelectedIndexChanged({
        # Refresh systems when site changes
        $browseSystemComboBox.DataSource = $null
        $selectedSiteId = if ($browseSiteComboBox.SelectedValue) { [int]$browseSiteComboBox.SelectedValue } else { 0 }
        if ($selectedSiteId -gt 0) {
            $systems = Get-Systems -SiteId $selectedSiteId
            if ($systems -and $systems.Rows.Count -gt 0) {
                $sysItems = New-Object System.Collections.ArrayList
                foreach ($row in $systems.Rows) {
                    $name = if ($row.System_Name -is [DBNull]) { '' } else { $row.System_Name.ToString() }
                    $null = $sysItems.Add([pscustomobject]@{ System_ID = [int]$row.System_ID; DisplayName = $name })
                }
                $browseSystemComboBox.DisplayMember = 'DisplayName'
                $browseSystemComboBox.ValueMember = 'System_ID'
                $browseSystemComboBox.DataSource = $sysItems
            }
        }
        # Refresh data with new filters
        Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox
    })
    
    $browseSystemComboBox.Add_SelectedIndexChanged({
        # Refresh data when system changes
        Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox
    })

    $browseSeverityComboBox.Add_SelectedIndexChanged({
        # Refresh data when severity filter changes
        Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox
    })

    $browseStatusComboBox.Add_SelectedIndexChanged({
        # Refresh data when status filter changes
        Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox
    })

    $refreshDataBtn.Add_Click({
        Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox
    })

    $clearFiltersBtn.Add_Click({
        $browseSiteComboBox.SelectedIndex = -1
        $browseSystemComboBox.SelectedIndex = -1
        $browseSeverityComboBox.SelectedIndex = 0  # Reset to "All"
        $browseStatusComboBox.SelectedIndex = 0    # Reset to "All"
        Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox
    })
    
    # CCI Management Event Handlers
    $importCciMgmtBtn.Add_Click({
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
        $openFileDialog.Title = "Select CCI Mappings XML File"
        
        if ($openFileDialog.ShowDialog() -eq "OK") {
            # Show progress bars
            $cciMgmtProgressBar.Visible = $true
            $cciMgmtProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
            $cciMgmtProgressBar.Maximum = 100
            $cciMgmtProgressBar.Value = 0
            
            $cciMgmtProgressLabel.Text = "Importing CCI mappings from: $($openFileDialog.FileName)"
            $cciManagementTab.Refresh()
            
            try {
                $fileName = Split-Path $openFileDialog.FileName -Leaf
                $result = Import-CciMappings -XmlPath $openFileDialog.FileName -SourceFile $fileName
                
                # Hide progress bars
                $cciMgmtProgressBar.Visible = $false
                
                if ($result.Success) {
                    $cciMgmtProgressLabel.Text = "Successfully imported $($result.Count) CCI mappings"
                    $cciMgmtProgressLabel.ForeColor = [System.Drawing.Color]::Green
                    Update-CciStatus -StatusLabel $cciStatusLabel -DataGrid $cciDataGrid
                    [System.Windows.Forms.MessageBox]::Show("Successfully imported $($result.Count) CCI mappings from $fileName", "Import Complete", "OK", "Information")
                } else {
                    $cciMgmtProgressLabel.Text = "Import failed: $($result.ErrorMessage)"
                    $cciMgmtProgressLabel.ForeColor = [System.Drawing.Color]::Red
                    [System.Windows.Forms.MessageBox]::Show("Import failed: $($result.ErrorMessage)", "Import Error", "OK", "Error")
                }
            }
            catch {
                $cciMgmtProgressBar.Visible = $false
                $cciMgmtProgressLabel.Text = "Import error: $($_.Exception.Message)"
                $cciMgmtProgressLabel.ForeColor = [System.Drawing.Color]::Red
                [System.Windows.Forms.MessageBox]::Show("Import error: $($_.Exception.Message)", "Import Error", "OK", "Error")
            }
        }
    })
    
    $clearCciBtn.Add_Click({
        $result = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to clear all CCI data? This action cannot be undone.", "Confirm Clear", "YesNo", "Warning")
        if ($result -eq "Yes") {
            if (Clear-CciData) {
                Update-CciStatus -StatusLabel $cciStatusLabel -DataGrid $cciDataGrid
                $cciMgmtProgressLabel.Text = "CCI data cleared successfully"
                $cciMgmtProgressLabel.ForeColor = [System.Drawing.Color]::Green
            } else {
                $cciMgmtProgressLabel.Text = "Failed to clear CCI data"
                $cciMgmtProgressLabel.ForeColor = [System.Drawing.Color]::Red
            }
        }
    })
    
    $refreshCciStatusBtn.Add_Click({
        Update-CciStatus -StatusLabel $cciStatusLabel -DataGrid $cciDataGrid
        $cciMgmtProgressLabel.Text = "Status refreshed"
        $cciMgmtProgressLabel.ForeColor = [System.Drawing.Color]::DarkBlue
    })
    
    $exitMenu.Add_Click({ $form.Close() })
    
    # Management Event Handlers
    $sitesListBox.Add_SelectedIndexChanged({
        if ($script:IsRefreshingMgmt) { return }
        if ($sitesListBox.SelectedIndex -lt 0) { return }
        
        try {
            $script:IsRefreshingMgmt = $true
            $systemsListBox.DataSource = $null
            $siteId = [int]$sitesListBox.SelectedValue
            $systems = Get-Systems -SiteId $siteId
            if ($systems -and $systems.Rows.Count -gt 0) {
                $systemsListBox.DisplayMember = 'System_Name'
                $systemsListBox.ValueMember = 'System_ID'
                $systemsListBox.DataSource = $systems
            }
        }
        finally {
            $script:IsRefreshingMgmt = $false
        }
    })
    
    $addSiteBtn.Add_Click({
        $inputForm = New-Object System.Windows.Forms.Form
        $inputForm.Text = "Add New Site"
        $inputForm.Size = New-Object System.Drawing.Size(400, 250)
        $inputForm.StartPosition = "CenterParent"
        
        $nameLabel = New-Object System.Windows.Forms.Label
        $nameLabel.Text = "Site Name:"
        $nameLabel.Location = New-Object System.Drawing.Point(20, 20)
        $nameLabel.Size = New-Object System.Drawing.Size(80, 20)
        $inputForm.Controls.Add($nameLabel)
        
        $nameBox = New-Object System.Windows.Forms.TextBox
        $nameBox.Location = New-Object System.Drawing.Point(110, 17)
        $nameBox.Size = New-Object System.Drawing.Size(250, 25)
        $inputForm.Controls.Add($nameBox)
        
        $locLabel = New-Object System.Windows.Forms.Label
        $locLabel.Text = "Location:"
        $locLabel.Location = New-Object System.Drawing.Point(20, 60)
        $locLabel.Size = New-Object System.Drawing.Size(80, 20)
        $inputForm.Controls.Add($locLabel)
        
        $locBox = New-Object System.Windows.Forms.TextBox
        $locBox.Location = New-Object System.Drawing.Point(110, 57)
        $locBox.Size = New-Object System.Drawing.Size(250, 25)
        $inputForm.Controls.Add($locBox)
        
        $descLabel = New-Object System.Windows.Forms.Label
        $descLabel.Text = "Description:"
        $descLabel.Location = New-Object System.Drawing.Point(20, 100)
        $descLabel.Size = New-Object System.Drawing.Size(80, 20)
        $inputForm.Controls.Add($descLabel)
        
        $descBox = New-Object System.Windows.Forms.TextBox
        $descBox.Location = New-Object System.Drawing.Point(110, 97)
        $descBox.Size = New-Object System.Drawing.Size(250, 60)
        $descBox.Multiline = $true
        $inputForm.Controls.Add($descBox)
        
        $okBtn = New-Object System.Windows.Forms.Button
        $okBtn.Text = "Add"
        $okBtn.Location = New-Object System.Drawing.Point(200, 170)
        $okBtn.Size = New-Object System.Drawing.Size(75, 30)
        $okBtn.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $inputForm.Controls.Add($okBtn)
        
        $cancelBtn = New-Object System.Windows.Forms.Button
        $cancelBtn.Text = "Cancel"
        $cancelBtn.Location = New-Object System.Drawing.Point(285, 170)
        $cancelBtn.Size = New-Object System.Drawing.Size(75, 30)
        $cancelBtn.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $inputForm.Controls.Add($cancelBtn)
        
        $inputForm.AcceptButton = $okBtn
        $inputForm.CancelButton = $cancelBtn
        
        if ($inputForm.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            if ([string]::IsNullOrWhiteSpace($nameBox.Text)) {
                [System.Windows.Forms.MessageBox]::Show("Site name is required.", "Validation Error", "OK", "Warning")
                $mgmtStatusLabel.Text = "Validation Error: Site name is required"
                $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Red
                return
            }
            
            $mgmtStatusLabel.Text = "Adding site '$($nameBox.Text)'..."
            $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Blue
            
            if (Add-Site -SiteName $nameBox.Text -Description $descBox.Text -Location $locBox.Text) {
                [System.Windows.Forms.MessageBox]::Show("Site added successfully!", "Success", "OK", "Information")
                $mgmtStatusLabel.Text = "✓ Site '$($nameBox.Text)' added successfully"
                $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Green
                Refresh-ManagementLists -SitesListBox $sitesListBox -SystemsListBox $systemsListBox
            }
            else {
                $mgmtStatusLabel.Text = "✗ Failed to add site"
                $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Red
            }
        }
    })
    
    $deleteSiteBtn.Add_Click({
        if ($sitesListBox.SelectedIndex -lt 0) {
            [System.Windows.Forms.MessageBox]::Show("Please select a site to delete.", "Information", "OK", "Information")
            $mgmtStatusLabel.Text = "Please select a site first"
            $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Orange
            return
        }
        
        if (-not $script:SitesList -or $script:SitesList.Count -le $sitesListBox.SelectedIndex) { return }
        $selectedSite = $script:SitesList[$sitesListBox.SelectedIndex]
        $siteName = $selectedSite.SiteName
        $siteId = $selectedSite.SiteID
        
        $result = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to delete '$siteName'?", "Confirm Delete", "YesNo", "Warning")
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            $mgmtStatusLabel.Text = "Deleting site '$siteName'..."
            $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Blue
            
            $deleteResult = Remove-Site -SiteId $siteId
            if ($deleteResult.Success) {
                [System.Windows.Forms.MessageBox]::Show("Site deleted successfully!", "Success", "OK", "Information")
                $mgmtStatusLabel.Text = "✓ Site '$siteName' deleted successfully"
                $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Green
                Refresh-ManagementLists -SitesListBox $sitesListBox -SystemsListBox $systemsListBox
            }
            else {
                [System.Windows.Forms.MessageBox]::Show($deleteResult.Error, "Error", "OK", "Error")
                $mgmtStatusLabel.Text = "✗ $($deleteResult.Error)"
                $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Red
            }
        }
    })
    
    $addSystemBtn.Add_Click({
        if ($sitesListBox.SelectedIndex -lt 0) {
            [System.Windows.Forms.MessageBox]::Show("Please select a site first.", "Information", "OK", "Information")
            $mgmtStatusLabel.Text = "Please select a site first"
            $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Orange
            return
        }
        
        $siteId = [int]$sitesListBox.SelectedValue
        
        $inputForm = New-Object System.Windows.Forms.Form
        $inputForm.Text = "Add New System"
        $inputForm.Size = New-Object System.Drawing.Size(400, 300)
        $inputForm.StartPosition = "CenterParent"
        
        $nameLabel = New-Object System.Windows.Forms.Label
        $nameLabel.Text = "System Name:"
        $nameLabel.Location = New-Object System.Drawing.Point(20, 20)
        $nameLabel.Size = New-Object System.Drawing.Size(90, 20)
        $inputForm.Controls.Add($nameLabel)
        
        $nameBox = New-Object System.Windows.Forms.TextBox
        $nameBox.Location = New-Object System.Drawing.Point(115, 17)
        $nameBox.Size = New-Object System.Drawing.Size(250, 25)
        $inputForm.Controls.Add($nameBox)
        
        $hostLabel = New-Object System.Windows.Forms.Label
        $hostLabel.Text = "Hostname:"
        $hostLabel.Location = New-Object System.Drawing.Point(20, 60)
        $hostLabel.Size = New-Object System.Drawing.Size(90, 20)
        $inputForm.Controls.Add($hostLabel)
        
        $hostBox = New-Object System.Windows.Forms.TextBox
        $hostBox.Location = New-Object System.Drawing.Point(115, 57)
        $hostBox.Size = New-Object System.Drawing.Size(250, 25)
        $inputForm.Controls.Add($hostBox)
        
        $ipLabel = New-Object System.Windows.Forms.Label
        $ipLabel.Text = "IP Address:"
        $ipLabel.Location = New-Object System.Drawing.Point(20, 100)
        $ipLabel.Size = New-Object System.Drawing.Size(90, 20)
        $inputForm.Controls.Add($ipLabel)
        
        $ipBox = New-Object System.Windows.Forms.TextBox
        $ipBox.Location = New-Object System.Drawing.Point(115, 97)
        $ipBox.Size = New-Object System.Drawing.Size(250, 25)
        $inputForm.Controls.Add($ipBox)
        
        $descLabel = New-Object System.Windows.Forms.Label
        $descLabel.Text = "Description:"
        $descLabel.Location = New-Object System.Drawing.Point(20, 140)
        $descLabel.Size = New-Object System.Drawing.Size(90, 20)
        $inputForm.Controls.Add($descLabel)
        
        $descBox = New-Object System.Windows.Forms.TextBox
        $descBox.Location = New-Object System.Drawing.Point(115, 137)
        $descBox.Size = New-Object System.Drawing.Size(250, 60)
        $descBox.Multiline = $true
        $inputForm.Controls.Add($descBox)
        
        $okBtn = New-Object System.Windows.Forms.Button
        $okBtn.Text = "Add"
        $okBtn.Location = New-Object System.Drawing.Point(200, 210)
        $okBtn.Size = New-Object System.Drawing.Size(75, 30)
        $okBtn.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $inputForm.Controls.Add($okBtn)
        
        $cancelBtn = New-Object System.Windows.Forms.Button
        $cancelBtn.Text = "Cancel"
        $cancelBtn.Location = New-Object System.Drawing.Point(285, 210)
        $cancelBtn.Size = New-Object System.Drawing.Size(75, 30)
        $cancelBtn.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $inputForm.Controls.Add($cancelBtn)
        
        $inputForm.AcceptButton = $okBtn
        $inputForm.CancelButton = $cancelBtn
        
        if ($inputForm.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            if ([string]::IsNullOrWhiteSpace($nameBox.Text)) {
                [System.Windows.Forms.MessageBox]::Show("System name is required.", "Validation Error", "OK", "Warning")
                $mgmtStatusLabel.Text = "Validation Error: System name is required"
                $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Red
                return
            }
            
            $mgmtStatusLabel.Text = "Adding system '$($nameBox.Text)'..."
            $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Blue
            
            if (Add-System -SiteId $siteId -SystemName $nameBox.Text -Description $descBox.Text -IPAddress $ipBox.Text -Hostname $hostBox.Text) {
                [System.Windows.Forms.MessageBox]::Show("System added successfully!", "Success", "OK", "Information")
                $mgmtStatusLabel.Text = "✓ System '$($nameBox.Text)' added successfully"
                $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Green
                Refresh-ManagementLists -SitesListBox $sitesListBox -SystemsListBox $systemsListBox
            }
            else {
                $mgmtStatusLabel.Text = "✗ Failed to add system"
                $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Red
            }
        }
    })
    
    $deleteSystemBtn.Add_Click({
        if ($systemsListBox.SelectedIndex -lt 0) {
            [System.Windows.Forms.MessageBox]::Show("Please select a system to delete.", "Information", "OK", "Information")
            $mgmtStatusLabel.Text = "Please select a system first"
            $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Orange
            return
        }
        
        if (-not $script:SystemsList -or $script:SystemsList.Count -le $systemsListBox.SelectedIndex) { return }
        $selectedSystem = $script:SystemsList[$systemsListBox.SelectedIndex]
        $systemName = $selectedSystem.SystemName
        $systemId = $selectedSystem.SystemID
        
        $result = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to delete '$systemName'?", "Confirm Delete", "YesNo", "Warning")
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            $mgmtStatusLabel.Text = "Deleting system '$systemName'..."
            $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Blue
            
            $deleteResult = Remove-System -SystemId $systemId
            if ($deleteResult.Success) {
                [System.Windows.Forms.MessageBox]::Show("System deleted successfully!", "Success", "OK", "Information")
                $mgmtStatusLabel.Text = "✓ System '$systemName' deleted successfully"
                $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Green
                Refresh-ManagementLists -SitesListBox $sitesListBox -SystemsListBox $systemsListBox
            }
            else {
                [System.Windows.Forms.MessageBox]::Show($deleteResult.Error, "Error", "OK", "Error")
                $mgmtStatusLabel.Text = "✗ $($deleteResult.Error)"
                $mgmtStatusLabel.ForeColor = [System.Drawing.Color]::Red
            }
        }
    })
    
    # Initial load
    Refresh-Dashboard -DashboardTab $dashboardTab
    
    # Force refresh of Management tab lists on startup
    Write-Host "Debug: Forcing initial refresh of Management tab..." -ForegroundColor DarkGray
    Refresh-ManagementLists -SitesListBox $sitesListBox -SystemsListBox $systemsListBox
    
    # Force refresh of Import tab context selectors on startup
    Write-Host "Debug: Forcing initial refresh of Import tab..." -ForegroundColor DarkGray
    Refresh-ImportContextSelectors -ImportSiteCombo $importSiteComboBox -ImportSystemCombo $importSystemComboBox
    Update-ImportStatus -CciStatusLabel $cciStatusLabel -StigStatusLabel $stigStatusLabel -ImportSiteCombo $importSiteComboBox -ImportSystemCombo $importSystemComboBox
    
    # Force refresh of Browse Data filters on startup
    Write-Host "Debug: Forcing initial refresh of Browse Data filters..." -ForegroundColor DarkGray
    Refresh-BrowseFilters -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox
    
    # Force initial load of Browse Data
    Write-Host "Debug: Forcing initial load of Browse Data..." -ForegroundColor DarkGray
    Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel -SiteCombo $browseSiteComboBox -SystemCombo $browseSystemComboBox -SeverityCombo $browseSeverityComboBox -StatusCombo $browseStatusComboBox
    
    # Update CCI schema if needed
    Write-Host "Debug: Checking CCI schema..." -ForegroundColor DarkGray
    Update-CciSchema
    
    # Initialize CCI Management status
    Write-Host "Debug: Initializing CCI Management status..." -ForegroundColor DarkGray
    Update-CciStatus -StatusLabel $cciStatusLabel -DataGrid $cciDataGrid
    
    $form.Add_Shown({ $form.Activate() })
    [void]$form.ShowDialog()
}

#endregion

#region Main Entry Point

# Initialize database
Write-Host "Initializing STIG Analysis Application..." -ForegroundColor Cyan
$dbInitialized = Initialize-Database -DbPath $script:DatabasePath

if ($dbInitialized) {
    # Connect to database
    $script:DatabaseConnection = [DatabaseConnection]::new($script:DatabasePath)
    $connected = $script:DatabaseConnection.Connect()
    
    if ($connected) {
        Write-Host "Database connected successfully" -ForegroundColor Green
        Write-Host "Starting application..." -ForegroundColor Cyan
        
        # Show main application
        Show-MainApplication
        
        # Cleanup
        Write-Host "Closing database connection..." -ForegroundColor Cyan
        $script:DatabaseConnection.Disconnect()
        Write-Host "Application closed" -ForegroundColor Green
    }
    else {
        Write-Error "Failed to connect to database"
        [System.Windows.Forms.MessageBox]::Show("Failed to connect to database.", "Error", "OK", "Error")
        exit 1
    }
}
else {
    Write-Error "Failed to initialize database"
    [System.Windows.Forms.MessageBox]::Show("Failed to initialize database. Make sure Microsoft Access Database Engine 2016 is installed.", "Error", "OK", "Error")
    exit 1
}

#endregion

