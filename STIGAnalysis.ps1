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
        
        # CCI Mappings table
        $conn.ExecuteNonQuery(@"
CREATE TABLE CCI_Mappings (
    CCI_ID VARCHAR(20) PRIMARY KEY,
    NIST_Controls TEXT,
    Control_Families TEXT,
    Description TEXT
)
"@) | Out-Null
        
        # STIG Files table
        $conn.ExecuteNonQuery(@"
CREATE TABLE STIG_Files (
    File_ID AUTOINCREMENT PRIMARY KEY,
    File_Name VARCHAR(255),
    STIG_Title VARCHAR(255),
    Import_Date DATETIME,
    Record_Count INTEGER
)
"@) | Out-Null
        
        # Vulnerabilities table
        $conn.ExecuteNonQuery(@"
CREATE TABLE Vulnerabilities (
    Vulnerability_ID AUTOINCREMENT PRIMARY KEY,
    File_ID INTEGER,
    Group_ID VARCHAR(50),
    Rule_ID VARCHAR(50),
    Rule_Title TEXT,
    Severity VARCHAR(20),
    Status VARCHAR(50),
    STIG_Name VARCHAR(255),
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

#region CCI Import

function Import-CciMappings {
    param([string]$XmlPath)
    
    try {
        [xml]$cciXml = Get-Content -Path $XmlPath -Raw
        $count = 0
        
        $ns = New-Object System.Xml.XmlNamespaceManager($cciXml.NameTable)
        $ns.AddNamespace("cci", "http://iase.disa.mil/cci")
        
        $cciItems = $cciXml.SelectNodes("//cci:cci_item", $ns)
        
        # Clear existing mappings
        $script:DatabaseConnection.ExecuteNonQuery("DELETE FROM CCI_Mappings") | Out-Null
        
        foreach ($cciItem in $cciItems) {
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
INSERT INTO CCI_Mappings (CCI_ID, NIST_Controls, Control_Families, Description)
VALUES ('$cciId', '$nistStr', '$families', '$desc')
"@) | Out-Null
                $count++
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
        [int]$FileId
    )
    
    try {
        [xml]$ckl = Get-Content -Path $Path -Raw
        $count = 0
        
        $stigName = $ckl.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA | 
            Where-Object { $_.SID_NAME -eq 'title' } | 
            Select-Object -ExpandProperty SID_DATA
        
        foreach ($vuln in $ckl.CHECKLIST.STIGS.iSTIG.VULN) {
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
    $button.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $button.Cursor = [System.Windows.Forms.Cursors]::Hand
    return $button
}

function Refresh-Dashboard {
    param($DashboardTab)
    
    # Clear existing controls
    $DashboardTab.Controls.Clear()
    
    # Get statistics
    $stats = @{
        TotalFiles = 0
        TotalVulns = 0
        Open = 0
        NotAFinding = 0
        NotReviewed = 0
        High = 0
        Medium = 0
        Low = 0
    }
    
    try {
        $filesData = $script:DatabaseConnection.ExecuteQuery("SELECT COUNT(*) AS cnt FROM STIG_Files")
        $stats.TotalFiles = $filesData.Rows[0].cnt
        
        $vulnsData = $script:DatabaseConnection.ExecuteQuery(@"
SELECT 
    COUNT(*) AS Total,
    SUM(IIF(Status='Open', 1, 0)) AS [Open],
    SUM(IIF(Status='NotAFinding' OR Status='Not_A_Finding', 1, 0)) AS NotAFinding,
    SUM(IIF(Status='Not_Reviewed', 1, 0)) AS NotReviewed,
    SUM(IIF(Severity='high' OR Severity='critical', 1, 0)) AS [High],
    SUM(IIF(Severity='medium', 1, 0)) AS Medium,
    SUM(IIF(Severity='low', 1, 0)) AS [Low]
FROM Vulnerabilities
"@)
        
        if ($vulnsData.Rows.Count -gt 0) {
            $row = $vulnsData.Rows[0]
            $stats.TotalVulns = if ($row.Total -is [DBNull]) { 0 } else { $row.Total }
            $stats.Open = if ($row.Open -is [DBNull]) { 0 } else { $row.Open }
            $stats.NotAFinding = if ($row.NotAFinding -is [DBNull]) { 0 } else { $row.NotAFinding }
            $stats.NotReviewed = if ($row.NotReviewed -is [DBNull]) { 0 } else { $row.NotReviewed }
            $stats.High = if ($row.High -is [DBNull]) { 0 } else { $row.High }
            $stats.Medium = if ($row.Medium -is [DBNull]) { 0 } else { $row.Medium }
            $stats.Low = if ($row.Low -is [DBNull]) { 0 } else { $row.Low }
        }
    }
    catch {
        Write-Warning "Error loading statistics: $_"
    }
    
    $complianceRate = if ($stats.TotalVulns -gt 0) { 
        [math]::Round(($stats.NotAFinding / $stats.TotalVulns) * 100, 1)
    } else { 0 }
    
    # Create stat cards
    $cardY = 20
    $cardX = 20
    $cardWidth = 180
    $cardHeight = 100
    $cardSpacing = 200
    
    $cards = @(
        @{Label="Total STIG Files"; Value=$stats.TotalFiles; Color=[System.Drawing.Color]::FromArgb(0, 120, 215)},
        @{Label="Total Findings"; Value=$stats.TotalVulns; Color=[System.Drawing.Color]::FromArgb(0, 120, 215)},
        @{Label="Open Findings"; Value=$stats.Open; Color=[System.Drawing.Color]::FromArgb(220, 53, 69)},
        @{Label="Compliance Rate"; Value="$complianceRate%"; Color=[System.Drawing.Color]::FromArgb(40, 167, 69)}
        @{Label="High Severity"; Value=$stats.High; Color=[System.Drawing.Color]::FromArgb(220, 53, 69)},
        @{Label="Medium Severity"; Value=$stats.Medium; Color=[System.Drawing.Color]::FromArgb(255, 193, 7)},
        @{Label="Low Severity"; Value=$stats.Low; Color=[System.Drawing.Color]::FromArgb(40, 167, 69)},
        @{Label="Not Reviewed"; Value=$stats.NotReviewed; Color=[System.Drawing.Color]::FromArgb(108, 117, 125)}
    )
    
    for ($i = 0; $i -lt $cards.Count; $i++) {
        $col = $i % 4
        $row = [math]::Floor($i / 4)
        
        $card = New-Object System.Windows.Forms.Panel
        $card.Location = New-Object System.Drawing.Point(($cardX + $col * $cardSpacing), ($cardY + $row * 120))
        $card.Size = New-Object System.Drawing.Size($cardWidth, $cardHeight)
        $card.BackColor = $cards[$i].Color
        
        $labelTitle = New-Object System.Windows.Forms.Label
        $labelTitle.Location = New-Object System.Drawing.Point(10, 10)
        $labelTitle.Size = New-Object System.Drawing.Size(160, 25)
        $labelTitle.Text = $cards[$i].Label
        $labelTitle.ForeColor = [System.Drawing.Color]::White
        $labelTitle.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $card.Controls.Add($labelTitle)
        
        $labelValue = New-Object System.Windows.Forms.Label
        $labelValue.Location = New-Object System.Drawing.Point(10, 40)
        $labelValue.Size = New-Object System.Drawing.Size(160, 50)
        $labelValue.Text = $cards[$i].Value
        $labelValue.ForeColor = [System.Drawing.Color]::White
        $labelValue.Font = New-Object System.Drawing.Font("Segoe UI", 24, [System.Drawing.FontStyle]::Bold)
        $labelValue.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
        $card.Controls.Add($labelValue)
        
        $DashboardTab.Controls.Add($card)
    }
    
    # Recent imports list
    $recentLabel = New-Object System.Windows.Forms.Label
    $recentLabel.Location = New-Object System.Drawing.Point(20, 260)
    $recentLabel.Size = New-Object System.Drawing.Size(800, 25)
    $recentLabel.Text = "Recent Imports"
    $recentLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $DashboardTab.Controls.Add($recentLabel)
    
    $recentGrid = New-Object System.Windows.Forms.DataGridView
    $recentGrid.Location = New-Object System.Drawing.Point(20, 290)
    $recentGrid.Size = New-Object System.Drawing.Size(820, 300)
    $recentGrid.ReadOnly = $true
    $recentGrid.AllowUserToAddRows = $false
    $recentGrid.SelectionMode = 'FullRowSelect'
    $recentGrid.BackgroundColor = [System.Drawing.Color]::White
    $recentGrid.AutoSizeColumnsMode = 'Fill'
    
    try {
        $recentData = $script:DatabaseConnection.ExecuteQuery(@"
SELECT 
    File_Name AS [File Name],
    STIG_Title AS [STIG Title],
    Import_Date AS [Import Date],
    Record_Count AS [Findings]
FROM STIG_Files
ORDER BY Import_Date DESC
"@)
        $recentGrid.DataSource = $recentData
    }
    catch {
        Write-Warning "Error loading recent imports: $_"
    }
    
    $DashboardTab.Controls.Add($recentGrid)
}

function Refresh-BrowseData {
    param($DataGrid, $StatusLabel)
    
    try {
        $StatusLabel.Text = "Loading data..."
        $StatusLabel.Refresh()
        
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
ORDER BY v.Severity DESC, v.Status
"@)
        
        $DataGrid.DataSource = $data
        $DataGrid.AutoSizeColumnsMode = 'Fill'
        
        # Color code severity column
        foreach ($row in $DataGrid.Rows) {
            $severity = $row.Cells["Severity"].Value
            if ($severity -eq "high" -or $severity -eq "critical") {
                $row.Cells["Severity"].Style.BackColor = [System.Drawing.Color]::FromArgb(255, 200, 200)
            }
            elseif ($severity -eq "medium") {
                $row.Cells["Severity"].Style.BackColor = [System.Drawing.Color]::FromArgb(255, 245, 200)
            }
            elseif ($severity -eq "low") {
                $row.Cells["Severity"].Style.BackColor = [System.Drawing.Color]::FromArgb(200, 255, 200)
            }
        }
        
        $StatusLabel.Text = "Loaded $($data.Rows.Count) vulnerabilities"
        $StatusLabel.ForeColor = [System.Drawing.Color]::Green
    }
    catch {
        $StatusLabel.Text = "Error loading data: $($_.Exception.Message)"
        $StatusLabel.ForeColor = [System.Drawing.Color]::Red
    }
}

#endregion

#region Main Form

function Show-MainApplication {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "STIG Analysis Desktop Application"
    $form.Size = New-Object System.Drawing.Size(1200, 800)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::White
    $form.MinimumSize = New-Object System.Drawing.Size(1000, 600)
    
    # Menu Bar
    $menuStrip = New-Object System.Windows.Forms.MenuStrip
    
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
    
    # Tab Control
    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Location = New-Object System.Drawing.Point(0, 28)
    $tabControl.Size = New-Object System.Drawing.Size(1184, 740)
    $tabControl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor 
                         [System.Windows.Forms.AnchorStyles]::Bottom -bor
                         [System.Windows.Forms.AnchorStyles]::Left -bor
                         [System.Windows.Forms.AnchorStyles]::Right
    
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
    $browseToolbar.Height = 50
    $browseToolbar.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
    
    $refreshDataBtn = New-StyledButton -Text "Refresh" -Location (New-Object System.Drawing.Point(10, 10)) -Size (New-Object System.Drawing.Size(100, 30))
    $browseToolbar.Controls.Add($refreshDataBtn)
    
    $searchLabel = New-Object System.Windows.Forms.Label
    $searchLabel.Text = "Search:"
    $searchLabel.Location = New-Object System.Drawing.Point(130, 15)
    $searchLabel.Size = New-Object System.Drawing.Size(60, 20)
    $browseToolbar.Controls.Add($searchLabel)
    
    $searchBox = New-Object System.Windows.Forms.TextBox
    $searchBox.Location = New-Object System.Drawing.Point(190, 12)
    $searchBox.Size = New-Object System.Drawing.Size(300, 25)
    $browseToolbar.Controls.Add($searchBox)
    
    $searchBtn = New-StyledButton -Text "Search" -Location (New-Object System.Drawing.Point(500, 10)) -Size (New-Object System.Drawing.Size(80, 30))
    $browseToolbar.Controls.Add($searchBtn)
    
    $browseTab.Controls.Add($browseToolbar)
    
    $browseDataGrid = New-Object System.Windows.Forms.DataGridView
    $browseDataGrid.Location = New-Object System.Drawing.Point(0, 50)
    $browseDataGrid.Size = New-Object System.Drawing.Size(1175, 610)
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
    
    $importPanel = New-Object System.Windows.Forms.Panel
    $importPanel.Location = New-Object System.Drawing.Point(50, 50)
    $importPanel.Size = New-Object System.Drawing.Size(700, 400)
    
    $cciGroupBox = New-Object System.Windows.Forms.GroupBox
    $cciGroupBox.Location = New-Object System.Drawing.Point(0, 0)
    $cciGroupBox.Size = New-Object System.Drawing.Size(700, 100)
    $cciGroupBox.Text = " Import CCI Mappings (U_CCI_List.xml) "
    $cciGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    
    $importCciBtn = New-StyledButton -Text "Import CCI File..." -Location (New-Object System.Drawing.Point(20, 30)) -Size (New-Object System.Drawing.Size(200, 40))
    $importCciBtn.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $cciGroupBox.Controls.Add($importCciBtn)
    
    $cciStatusLabel = New-Object System.Windows.Forms.Label
    $cciStatusLabel.Location = New-Object System.Drawing.Point(240, 35)
    $cciStatusLabel.Size = New-Object System.Drawing.Size(440, 30)
    $cciStatusLabel.Text = "No CCI mappings loaded"
    $cciStatusLabel.ForeColor = [System.Drawing.Color]::Gray
    $cciGroupBox.Controls.Add($cciStatusLabel)
    
    $importPanel.Controls.Add($cciGroupBox)
    
    $stigGroupBox = New-Object System.Windows.Forms.GroupBox
    $stigGroupBox.Location = New-Object System.Drawing.Point(0, 120)
    $stigGroupBox.Size = New-Object System.Drawing.Size(700, 100)
    $stigGroupBox.Text = " Import STIG Files (CKL/CKLB) "
    $stigGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    
    $importStigBtn = New-StyledButton -Text "Import STIG Files..." -Location (New-Object System.Drawing.Point(20, 30)) -Size (New-Object System.Drawing.Size(200, 40))
    $importStigBtn.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
    $stigGroupBox.Controls.Add($importStigBtn)
    
    $stigStatusLabel = New-Object System.Windows.Forms.Label
    $stigStatusLabel.Location = New-Object System.Drawing.Point(240, 35)
    $stigStatusLabel.Size = New-Object System.Drawing.Size(440, 30)
    $stigStatusLabel.Text = "No STIG files loaded"
    $stigStatusLabel.ForeColor = [System.Drawing.Color]::Gray
    $stigGroupBox.Controls.Add($stigStatusLabel)
    
    $importPanel.Controls.Add($stigGroupBox)
    
    $importTab.Controls.Add($importPanel)
    $tabControl.Controls.Add($importTab)
    
    $form.Controls.Add($tabControl)
    
    # Status Bar
    $statusBar = New-Object System.Windows.Forms.StatusStrip
    $statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusLabel.Text = "Ready | Database: $script:DatabasePath"
    [void]$statusBar.Items.Add($statusLabel)
    $form.Controls.Add($statusBar)
    
    # Event Handlers
    $importCciBtn.Add_Click({
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Filter = "CCI List XML (*.xml)|*.xml"
        $openFileDialog.Title = "Select U_CCI_List.xml"
        
        if ($openFileDialog.ShowDialog() -eq "OK") {
            $cciStatusLabel.Text = "Importing..."
            $cciStatusLabel.Refresh()
            
            $result = Import-CciMappings -XmlPath $openFileDialog.FileName
            
            if ($result.Success) {
                $cciStatusLabel.Text = "✓ Loaded $($result.Count) CCI mappings"
                $cciStatusLabel.ForeColor = [System.Drawing.Color]::Green
                [System.Windows.Forms.MessageBox]::Show("Successfully imported $($result.Count) CCI mappings!", "Success", "OK", "Information")
            }
            else {
                $cciStatusLabel.Text = "✗ Import failed"
                $cciStatusLabel.ForeColor = [System.Drawing.Color]::Red
                [System.Windows.Forms.MessageBox]::Show("Failed: $($result.Error)", "Error", "OK", "Error")
            }
        }
    })
    
    $importCciMenu.Add_Click($importCciBtn.GetInvocationList()[0])
    
    $importStigBtn.Add_Click({
        # Check if CCI mappings exist
        $cciCount = $script:DatabaseConnection.ExecuteQuery("SELECT COUNT(*) AS cnt FROM CCI_Mappings")
        if ($cciCount.Rows[0].cnt -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("Please import CCI mappings first.", "Information", "OK", "Information")
            return
        }
        
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Filter = "STIG Files (*.ckl;*.cklb)|*.ckl;*.cklb"
        $openFileDialog.Title = "Select STIG Files"
        $openFileDialog.Multiselect = $true
        
        if ($openFileDialog.ShowDialog() -eq "OK") {
            $totalImported = 0
            $totalVulns = 0
            
            foreach ($file in $openFileDialog.FileNames) {
                $fileName = Split-Path -Path $file -Leaf
                $extension = [System.IO.Path]::GetExtension($file).ToLower()
                
                $stigStatusLabel.Text = "Importing $fileName..."
                $stigStatusLabel.Refresh()
                
                # Check if already imported
                $existing = $script:DatabaseConnection.ExecuteQuery("SELECT File_ID FROM STIG_Files WHERE File_Name = '$fileName'")
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
                
                $stigTitleEsc = $stigTitle -replace "'", "''"
                
                if ($existing.Rows.Count -eq 0) {
                    # Insert STIG file record
                    $script:DatabaseConnection.ExecuteNonQuery(@"
INSERT INTO STIG_Files (File_Name, STIG_Title, Import_Date, Record_Count)
VALUES ('$fileName', '$stigTitleEsc', NOW(), 0)
"@) | Out-Null
                    
                    $fileIdResult = $script:DatabaseConnection.ExecuteQuery("SELECT @@IDENTITY AS FileID")
                    $fileId = $fileIdResult.Rows[0].FileID
                    
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
                    }
                }
            }
            
            if ($totalImported -gt 0) {
                $stigStatusLabel.Text = "✓ Imported $totalImported files with $totalVulns findings"
                $stigStatusLabel.ForeColor = [System.Drawing.Color]::Green
                [System.Windows.Forms.MessageBox]::Show("Successfully imported $totalImported STIG files with $totalVulns total findings!", "Success", "OK", "Information")
                
                # Refresh dashboard
                Refresh-Dashboard -DashboardTab $dashboardTab
            }
            else {
                $stigStatusLabel.Text = "All files already imported"
                $stigStatusLabel.ForeColor = [System.Drawing.Color]::Gray
            }
        }
    })
    
    $importStigMenu.Add_Click($importStigBtn.GetInvocationList()[0])
    
    $refreshDataBtn.Add_Click({
        Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel
    })
    
    $searchBtn.Add_Click({
        $searchTerm = $searchBox.Text
        if ([string]::IsNullOrWhiteSpace($searchTerm)) {
            Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel
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
            Refresh-BrowseData -DataGrid $browseDataGrid -StatusLabel $browseStatusLabel
        }
    })
    
    $exitMenu.Add_Click({ $form.Close() })
    
    # Initial load
    Refresh-Dashboard -DashboardTab $dashboardTab
    
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
