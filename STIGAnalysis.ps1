<#
.SYNOPSIS
    STIG Analysis Tool - Single Script with Database Persistence

.DESCRIPTION
    Analyzes STIG CKL/CKLB files, maps to NIST controls, and exports to Excel.
    Uses MS Access 2016 for persistent storage.

.NOTES
    Requirements: Windows 10, PowerShell 5.1+, Microsoft Access Database Engine 2016, Microsoft Office 2016+
    Version: 2.0 - Single Script Edition
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
$script:DatabasePath = "STIGAnalysis.accdb"
$script:DatabaseConnection = $null
$script:CciMappings = @{}
$script:VulnerabilityData = @()
$script:LoadedFiles = @()

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

#region Vulnerability Class

class Vulnerability {
    [string]$GroupId
    [string]$RuleId
    [string]$RuleVersion
    [string]$RuleTitle
    [string]$Severity
    [string]$Status
    [string]$StigName
    [string[]]$CCIs
    [string[]]$NistControls
    [string[]]$Families
    [string]$Discussion
    [string]$CheckContent
    [string]$FixText
    [string]$FindingDetails
    [string]$Comments
    [string]$SourceFile
}

#endregion

#region Database Initialization

function Initialize-Database {
    param([string]$DbPath)
    
    if (Test-Path $DbPath) {
        Write-Host "Database exists, connecting..." -ForegroundColor Green
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
    Control_Families TEXT
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
    Comments TEXT
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
        $mappings = @{}
        $count = 0
        
        $ns = New-Object System.Xml.XmlNamespaceManager($cciXml.NameTable)
        $ns.AddNamespace("cci", "http://iase.disa.mil/cci")
        
        $cciItems = $cciXml.SelectNodes("//cci:cci_item", $ns)
        
        foreach ($cciItem in $cciItems) {
            $cciId = $cciItem.GetAttribute("id")
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
                $mappings[$cciId] = $nistControls | Select-Object -Unique
                $count++
                
                # Save to database
                $nistStr = ($nistControls -join ', ')
                $families = ($nistControls | ForEach-Object { 
                    if ($_ -match '^([A-Z]{2,3})-') { $matches[1] }
                } | Select-Object -Unique) -join ', '
                
                $script:DatabaseConnection.ExecuteNonQuery(@"
INSERT INTO CCI_Mappings (CCI_ID, NIST_Controls, Control_Families)
VALUES ('$cciId', '$nistStr', '$families')
"@) | Out-Null
            }
        }
        
        return @{
            Success = $true
            Mappings = $mappings
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
        [hashtable]$CciMappings
    )
    
    try {
        [xml]$ckl = Get-Content -Path $Path -Raw
        $vulnerabilities = [System.Collections.ArrayList]::new()
        
        $stigName = $ckl.CHECKLIST.STIGS.iSTIG.STIG_INFO.SI_DATA | 
            Where-Object { $_.SID_NAME -eq 'title' } | 
            Select-Object -ExpandProperty SID_DATA
        
        foreach ($vuln in $ckl.CHECKLIST.STIGS.iSTIG.VULN) {
            $v = [Vulnerability]::new()
            
            $v.GroupId = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Vuln_Num' }).ATTRIBUTE_DATA
            $v.RuleId = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Rule_ID' }).ATTRIBUTE_DATA
            $v.RuleVersion = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Rule_Ver' }).ATTRIBUTE_DATA
            $v.RuleTitle = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Rule_Title' }).ATTRIBUTE_DATA
            $v.Severity = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Severity' }).ATTRIBUTE_DATA
            $v.Discussion = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Vuln_Discuss' }).ATTRIBUTE_DATA
            $v.CheckContent = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Check_Content' }).ATTRIBUTE_DATA
            $v.FixText = ($vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'Fix_Text' }).ATTRIBUTE_DATA.'#text'
            
            $cciRefs = $vuln.STIG_DATA | Where-Object { $_.VULN_ATTRIBUTE -eq 'CCI_REF' }
            if ($cciRefs) {
                $v.CCIs = @($cciRefs | ForEach-Object { $_.ATTRIBUTE_DATA } | Where-Object { $_ })
            } else {
                $v.CCIs = @()
            }
            
            $nistControls = [System.Collections.Generic.HashSet[string]]::new()
            $families = [System.Collections.Generic.HashSet[string]]::new()
            
            foreach ($cci in $v.CCIs) {
                if ($CciMappings.ContainsKey($cci)) {
                    foreach ($control in $CciMappings[$cci]) {
                        [void]$nistControls.Add($control)
                        if ($control -match '^([A-Z]{2,3})-') {
                            [void]$families.Add($matches[1])
                        }
                    }
                }
            }
            
            $v.NistControls = @($nistControls)
            $v.Families = @($families)
            $v.Status = $vuln.STATUS
            $v.FindingDetails = $vuln.FINDING_DETAILS
            $v.Comments = $vuln.COMMENTS
            $v.StigName = $stigName
            $v.SourceFile = Split-Path -Path $Path -Leaf
            
            [void]$vulnerabilities.Add($v)
        }
        
        return @{
            Success = $true
            Vulnerabilities = $vulnerabilities
            Count = $vulnerabilities.Count
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
        [hashtable]$CciMappings
    )
    
    try {
        $jsonContent = Get-Content -Path $Path -Raw | ConvertFrom-Json
        $vulnerabilities = [System.Collections.ArrayList]::new()
        
        $stigName = $jsonContent.title
        
        foreach ($vuln in $jsonContent.stigs.rules) {
            $v = [Vulnerability]::new()
            
            $v.GroupId = $vuln.group_id
            $v.RuleId = $vuln.rule_id
            $v.RuleVersion = $vuln.rule_version
            $v.RuleTitle = $vuln.rule_title
            $v.Severity = $vuln.severity
            $v.Discussion = $vuln.discussion
            $v.CheckContent = $vuln.check_content
            $v.FixText = $vuln.fix_text
            
            $cciList = @()
            if ($vuln.cci) { $cciList += @($vuln.cci) }
            if ($vuln.ccis) { $cciList += @($vuln.ccis) }
            if ($vuln.cci_refs) { $cciList += @($vuln.cci_refs) }
            $v.CCIs = $cciList | Select-Object -Unique | Where-Object { $_ }
            
            $nistControls = [System.Collections.Generic.HashSet[string]]::new()
            $families = [System.Collections.Generic.HashSet[string]]::new()
            
            foreach ($cci in $v.CCIs) {
                if ($CciMappings.ContainsKey($cci)) {
                    foreach ($control in $CciMappings[$cci]) {
                        [void]$nistControls.Add($control)
                        if ($control -match '^([A-Z]{2,3})-') {
                            [void]$families.Add($matches[1])
                        }
                    }
                }
            }
            
            $v.NistControls = @($nistControls)
            $v.Families = @($families)
            $v.Status = $vuln.status
            $v.FindingDetails = $vuln.finding_details
            $v.Comments = $vuln.comments
            $v.StigName = $stigName
            $v.SourceFile = Split-Path -Path $Path -Leaf
            
            [void]$vulnerabilities.Add($v)
        }
        
        return @{
            Success = $true
            Vulnerabilities = $vulnerabilities
            Count = $vulnerabilities.Count
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

#region Database Save

function Save-ToDatabase {
    param(
        [string]$FileName,
        [string]$StigTitle,
        [array]$Vulnerabilities
    )
    
    try {
        # Insert STIG file record
        $script:DatabaseConnection.ExecuteNonQuery(@"
INSERT INTO STIG_Files (File_Name, STIG_Title, Import_Date, Record_Count)
VALUES ('$FileName', '$StigTitle', NOW(), $($Vulnerabilities.Count))
"@) | Out-Null
        
        # Get the File_ID
        $fileIdResult = $script:DatabaseConnection.ExecuteQuery("SELECT @@IDENTITY AS FileID")
        $fileId = $fileIdResult.Rows[0].FileID
        
        # Insert vulnerabilities
        foreach ($v in $Vulnerabilities) {
            $cciStr = ($v.CCIs -join ', ') -replace "'", "''"
            $nistStr = ($v.NistControls -join ', ') -replace "'", "''"
            $familiesStr = ($v.Families -join ', ') -replace "'", "''"
            $discussion = ($v.Discussion -replace "'", "''")
            $checkContent = ($v.CheckContent -replace "'", "''")
            $fixText = ($v.FixText -replace "'", "''")
            $findingDetails = ($v.FindingDetails -replace "'", "''")
            $comments = ($v.Comments -replace "'", "''")
            $ruleTitle = ($v.RuleTitle -replace "'", "''")
            
            $script:DatabaseConnection.ExecuteNonQuery(@"
INSERT INTO Vulnerabilities (File_ID, Group_ID, Rule_ID, Rule_Title, Severity, Status, STIG_Name,
    CCI_References, NIST_Controls, Control_Families, Discussion, Check_Content, Fix_Text, Finding_Details, Comments)
VALUES ($fileId, '$($v.GroupId)', '$($v.RuleId)', '$ruleTitle', '$($v.Severity)', '$($v.Status)', '$($v.StigName)',
    '$cciStr', '$nistStr', '$familiesStr', '$discussion', '$checkContent', '$fixText', '$findingDetails', '$comments')
"@) | Out-Null
        }
        
        Write-Host "Saved $($Vulnerabilities.Count) vulnerabilities to database" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Warning "Failed to save to database: $($_.Exception.Message)"
        return $false
    }
}

#endregion

#region Excel Export (from old script)

function Export-ToExcel {
    param(
        [array]$Vulnerabilities,
        [string]$OutputPath
    )
    
    $excel = $null
    $workbook = $null
    
    try {
        Write-Host "Creating Excel workbook..." -ForegroundColor Cyan
        
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $excel.DisplayAlerts = $false
        $workbook = $excel.Workbooks.Add()
        
        # Group by STIG file
        $stigGroups = $Vulnerabilities | Group-Object -Property SourceFile
        
        $headers = @(
            'NIST Controls', 'NIST Family', 'CCIs', 'Vuln-ID', 'Rule-ID',
            'Title', 'Severity', 'Status', 'STIG Name',
            'Discussion', 'Check Content', 'Fix Text', 'Finding Details', 'Comments'
        )
        
        # Create sheets for each STIG file
        foreach ($stigGroup in $stigGroups) {
            $sheetName = $stigGroup.Name -replace '\.(ckl|cklb)$', '' -replace '[:\\\/\[\]\*\?<\>\|\-]', '_'
            if ($sheetName.Length -gt 31) { $sheetName = $sheetName.Substring(0, 31) }
            
            $worksheet = $workbook.Worksheets.Add()
            $worksheet.Name = $sheetName
            
            # Headers
            for ($col = 1; $col -le $headers.Count; $col++) {
                $worksheet.Cells.Item(1, $col) = $headers[$col - 1]
                $worksheet.Cells.Item(1, $col).Font.Bold = $true
            }
            
            # Data
            $row = 2
            foreach ($v in $stigGroup.Group) {
                $worksheet.Cells.Item($row, 1) = ($v.NistControls -join ', ')
                $worksheet.Cells.Item($row, 2) = ($v.Families -join ', ')
                $worksheet.Cells.Item($row, 3) = ($v.CCIs -join ', ')
                $worksheet.Cells.Item($row, 4) = $v.GroupId
                $worksheet.Cells.Item($row, 5) = $v.RuleId
                $worksheet.Cells.Item($row, 6) = $v.RuleTitle
                $worksheet.Cells.Item($row, 7) = $v.Severity
                $worksheet.Cells.Item($row, 8) = $v.Status
                $worksheet.Cells.Item($row, 9) = $v.StigName
                $worksheet.Cells.Item($row, 10) = $v.Discussion
                $worksheet.Cells.Item($row, 11) = $v.CheckContent
                $worksheet.Cells.Item($row, 12) = $v.FixText
                $worksheet.Cells.Item($row, 13) = $v.FindingDetails
                $worksheet.Cells.Item($row, 14) = $v.Comments
                $row++
            }
            
            # Auto-fit columns
            $worksheet.UsedRange.EntireColumn.AutoFit() | Out-Null
        }
        
        # Remove default sheet
        try {
            $workbook.Worksheets.Item("Sheet1").Delete()
        } catch {}
        
        # Save
        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
        $workbook.SaveAs($fullPath, 51)
        $workbook.Close($false)
        
        Write-Host "Excel file created: $OutputPath" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Excel export failed: $($_.Exception.Message)"
        return $false
    }
    finally {
        if ($workbook) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($workbook) | Out-Null }
        if ($excel) {
            $excel.Quit()
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) | Out-Null
        }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

#endregion

#region GUI

function Show-MainForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "STIG Analysis Tool v2.0"
    $form.Size = New-Object System.Drawing.Size(900, 650)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 245)
    
    # Header
    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.Location = New-Object System.Drawing.Point(0, 0)
    $headerPanel.Size = New-Object System.Drawing.Size(900, 70)
    $headerPanel.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $form.Controls.Add($headerPanel)
    
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $titleLabel.Size = New-Object System.Drawing.Size(600, 30)
    $titleLabel.Text = "STIG to NIST Control Mapper (Database Edition)"
    $titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $titleLabel.ForeColor = [System.Drawing.Color]::White
    $headerPanel.Controls.Add($titleLabel)
    
    # CCI Group
    $cciGroupBox = New-Object System.Windows.Forms.GroupBox
    $cciGroupBox.Location = New-Object System.Drawing.Point(20, 90)
    $cciGroupBox.Size = New-Object System.Drawing.Size(850, 90)
    $cciGroupBox.Text = " 1. CCI Mappings (U_CCI_List.xml) "
    $cciGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($cciGroupBox)
    
    $cciTextBox = New-Object System.Windows.Forms.TextBox
    $cciTextBox.Location = New-Object System.Drawing.Point(15, 30)
    $cciTextBox.Size = New-Object System.Drawing.Size(650, 23)
    $cciTextBox.ReadOnly = $true
    $cciGroupBox.Controls.Add($cciTextBox)
    
    $cciBrowseBtn = New-Object System.Windows.Forms.Button
    $cciBrowseBtn.Location = New-Object System.Drawing.Point(675, 28)
    $cciBrowseBtn.Size = New-Object System.Drawing.Size(160, 28)
    $cciBrowseBtn.Text = "Browse & Import..."
    $cciBrowseBtn.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $cciBrowseBtn.ForeColor = [System.Drawing.Color]::White
    $cciBrowseBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $cciGroupBox.Controls.Add($cciBrowseBtn)
    
    $cciStatusLabel = New-Object System.Windows.Forms.Label
    $cciStatusLabel.Location = New-Object System.Drawing.Point(15, 60)
    $cciStatusLabel.Size = New-Object System.Drawing.Size(820, 20)
    $cciStatusLabel.Text = "No CCI mappings loaded"
    $cciStatusLabel.ForeColor = [System.Drawing.Color]::Gray
    $cciGroupBox.Controls.Add($cciStatusLabel)
    
    # STIG Files Group
    $stigGroupBox = New-Object System.Windows.Forms.GroupBox
    $stigGroupBox.Location = New-Object System.Drawing.Point(20, 200)
    $stigGroupBox.Size = New-Object System.Drawing.Size(850, 300)
    $stigGroupBox.Text = " 2. STIG Files (CKL/CKLB) "
    $stigGroupBox.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($stigGroupBox)
    
    $stigListBox = New-Object System.Windows.Forms.ListBox
    $stigListBox.Location = New-Object System.Drawing.Point(15, 30)
    $stigListBox.Size = New-Object System.Drawing.Size(650, 220)
    $stigGroupBox.Controls.Add($stigListBox)
    
    $stigAddBtn = New-Object System.Windows.Forms.Button
    $stigAddBtn.Location = New-Object System.Drawing.Point(675, 30)
    $stigAddBtn.Size = New-Object System.Drawing.Size(160, 30)
    $stigAddBtn.Text = "Add Files..."
    $stigAddBtn.BackColor = [System.Drawing.Color]::FromArgb(16, 124, 16)
    $stigAddBtn.ForeColor = [System.Drawing.Color]::White
    $stigAddBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $stigGroupBox.Controls.Add($stigAddBtn)
    
    $stigClearBtn = New-Object System.Windows.Forms.Button
    $stigClearBtn.Location = New-Object System.Drawing.Point(675, 70)
    $stigClearBtn.Size = New-Object System.Drawing.Size(160, 30)
    $stigClearBtn.Text = "Clear All"
    $stigClearBtn.BackColor = [System.Drawing.Color]::Gray
    $stigClearBtn.ForeColor = [System.Drawing.Color]::White
    $stigClearBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $stigGroupBox.Controls.Add($stigClearBtn)
    
    $stigStatsLabel = New-Object System.Windows.Forms.Label
    $stigStatsLabel.Location = New-Object System.Drawing.Point(15, 260)
    $stigStatsLabel.Size = New-Object System.Drawing.Size(820, 30)
    $stigStatsLabel.Text = "No STIG files loaded"
    $stigStatsLabel.ForeColor = [System.Drawing.Color]::Gray
    $stigGroupBox.Controls.Add($stigStatsLabel)
    
    # Export Button
    $exportBtn = New-Object System.Windows.Forms.Button
    $exportBtn.Location = New-Object System.Drawing.Point(20, 520)
    $exportBtn.Size = New-Object System.Drawing.Size(200, 40)
    $exportBtn.Text = "3. Export to Excel..."
    $exportBtn.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $exportBtn.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 215)
    $exportBtn.ForeColor = [System.Drawing.Color]::White
    $exportBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $exportBtn.Enabled = $false
    $form.Controls.Add($exportBtn)
    
    $exportStatusLabel = New-Object System.Windows.Forms.Label
    $exportStatusLabel.Location = New-Object System.Drawing.Point(230, 525)
    $exportStatusLabel.Size = New-Object System.Drawing.Size(640, 30)
    $exportStatusLabel.Text = "Load CCI mappings and STIG files to enable export"
    $exportStatusLabel.ForeColor = [System.Drawing.Color]::Gray
    $form.Controls.Add($exportStatusLabel)
    
    # Event Handlers
    $cciBrowseBtn.Add_Click({
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Filter = "CCI List XML (*.xml)|*.xml"
        $openFileDialog.Title = "Select U_CCI_List.xml"
        
        if ($openFileDialog.ShowDialog() -eq "OK") {
            $cciTextBox.Text = $openFileDialog.FileName
            $cciStatusLabel.Text = "Importing CCI mappings..."
            $form.Refresh()
            
            $result = Import-CciMappings -XmlPath $openFileDialog.FileName
            
            if ($result.Success) {
                $script:CciMappings = $result.Mappings
                $cciStatusLabel.Text = "[OK] Loaded $($result.Count) CCI mappings from database"
                $cciStatusLabel.ForeColor = [System.Drawing.Color]::Green
                
                if ($script:VulnerabilityData.Count -gt 0) {
                    $exportBtn.Enabled = $true
                }
            }
            else {
                [System.Windows.Forms.MessageBox]::Show("Failed: $($result.Error)", "Error", "OK", "Error")
                $cciStatusLabel.Text = "[ERROR] Failed to load CCI mappings"
                $cciStatusLabel.ForeColor = [System.Drawing.Color]::Red
            }
        }
    })
    
    $stigAddBtn.Add_Click({
        if ($script:CciMappings.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("Please load CCI mappings first.", "Information", "OK", "Information")
            return
        }
        
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Filter = "STIG Files (*.ckl;*.cklb)|*.ckl;*.cklb"
        $openFileDialog.Title = "Select STIG Files"
        $openFileDialog.Multiselect = $true
        
        if ($openFileDialog.ShowDialog() -eq "OK") {
            foreach ($file in $openFileDialog.FileNames) {
                $fileName = Split-Path -Path $file -Leaf
                
                if ($script:LoadedFiles -contains $fileName) {
                    continue
                }
                
                $extension = [System.IO.Path]::GetExtension($file).ToLower()
                $result = $null
                
                if ($extension -eq '.ckl' -or $extension -eq '.xml') {
                    $result = Import-CklFile -Path $file -CciMappings $script:CciMappings
                }
                elseif ($extension -eq '.cklb' -or $extension -eq '.json') {
                    $result = Import-CklbFile -Path $file -CciMappings $script:CciMappings
                }
                
                if ($result -and $result.Success) {
                    $script:VulnerabilityData += $result.Vulnerabilities
                    $script:LoadedFiles += $fileName
                    $stigListBox.Items.Add("$fileName ($($result.Count) findings)")
                    
                    # Save to database
                    Save-ToDatabase -FileName $fileName -StigTitle $result.Vulnerabilities[0].StigName -Vulnerabilities $result.Vulnerabilities
                }
            }
            
            $stigStatsLabel.Text = "[OK] Loaded $($script:LoadedFiles.Count) files with $($script:VulnerabilityData.Count) total findings"
            $stigStatsLabel.ForeColor = [System.Drawing.Color]::Green
            $exportBtn.Enabled = $true
        }
    })
    
    $stigClearBtn.Add_Click({
        $script:VulnerabilityData = @()
        $script:LoadedFiles = @()
        $stigListBox.Items.Clear()
        $stigStatsLabel.Text = "No STIG files loaded"
        $stigStatsLabel.ForeColor = [System.Drawing.Color]::Gray
        $exportBtn.Enabled = $false
    })
    
    $exportBtn.Add_Click({
        if ($script:VulnerabilityData.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No data to export.", "Information", "OK", "Information")
            return
        }
        
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "Excel Files (*.xlsx)|*.xlsx"
        $saveFileDialog.Title = "Save Excel Report"
        $saveFileDialog.FileName = "STIG-Analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').xlsx"
        
        if ($saveFileDialog.ShowDialog() -eq "OK") {
            $exportStatusLabel.Text = "Exporting to Excel..."
            $form.Refresh()
            
            $success = Export-ToExcel -Vulnerabilities $script:VulnerabilityData -OutputPath $saveFileDialog.FileName
            
            if ($success) {
                $exportStatusLabel.Text = "[OK] Exported $($script:VulnerabilityData.Count) findings"
                $exportStatusLabel.ForeColor = [System.Drawing.Color]::Green
                
                $openResult = [System.Windows.Forms.MessageBox]::Show("Export complete! Open file now?", "Success", "YesNo", "Information")
                if ($openResult -eq "Yes") {
                    Start-Process $saveFileDialog.FileName
                }
            }
            else {
                $exportStatusLabel.Text = "[ERROR] Export failed"
                $exportStatusLabel.ForeColor = [System.Drawing.Color]::Red
            }
        }
    })
    
    $form.Add_Shown({ $form.Activate() })
    [void]$form.ShowDialog()
}

#endregion

#region Main

# Check for Excel
try {
    $null = New-Object -ComObject Excel.Application -ErrorAction Stop
}
catch {
    [System.Windows.Forms.MessageBox]::Show("Microsoft Excel is not installed.", "Error", "OK", "Error")
    exit 1
}

# Initialize database
Write-Host "Initializing database..." -ForegroundColor Cyan
$dbInitialized = Initialize-Database -DbPath $script:DatabasePath

if ($dbInitialized) {
    # Connect to database
    $script:DatabaseConnection = [DatabaseConnection]::new($script:DatabasePath)
    $connected = $script:DatabaseConnection.Connect()
    
    if ($connected) {
        Write-Host "Connected to database" -ForegroundColor Green
        
        # Load existing CCI mappings from database
        try {
            $cciData = $script:DatabaseConnection.ExecuteQuery("SELECT CCI_ID, NIST_Controls FROM CCI_Mappings")
            $script:CciMappings = @{}
            foreach ($row in $cciData.Rows) {
                $script:CciMappings[$row.CCI_ID] = $row.NIST_Controls -split ', '
            }
            if ($script:CciMappings.Count -gt 0) {
                Write-Host "Loaded $($script:CciMappings.Count) existing CCI mappings from database" -ForegroundColor Green
            }
        }
        catch {
            Write-Verbose "No existing CCI mappings in database"
        }
        
        # Show GUI
        Show-MainForm
        
        # Cleanup
        $script:DatabaseConnection.Disconnect()
    }
    else {
        Write-Error "Failed to connect to database"
        exit 1
    }
}
else {
    Write-Error "Failed to initialize database"
    exit 1
}

#endregion

