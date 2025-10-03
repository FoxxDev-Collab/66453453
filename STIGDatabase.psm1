<#
.SYNOPSIS
    STIG Database Module for MS Access 2016 Integration

.DESCRIPTION
    This module provides comprehensive database operations for STIG analysis using MS Access 2016.
    It uses ADO.NET for high-performance database operations and supports all CRUD operations.

.NOTES
    Requirements: Windows 10, PowerShell 5.1+, Microsoft Access Database Engine 2016
    Author: STIG Analysis Tool
    Version: 2.0
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

# Add required assemblies
Add-Type -AssemblyName System.Data
Add-Type -AssemblyName System.Windows.Forms

# Script configuration
$ErrorActionPreference = 'Stop'

# ========================================
# DATABASE CONNECTION MANAGEMENT
# ========================================

class DatabaseConnection {
    [string]$ConnectionString
    [System.Data.OleDb.OleDbConnection]$Connection
    [bool]$IsConnected = $false

    DatabaseConnection([string]$DatabasePath) {
        # Build connection string for MS Access 2016
        $this.ConnectionString = @"
Provider=Microsoft.ACE.OLEDB.16.0;
Data Source=$DatabasePath;
Persist Security Info=False;
"@

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

    [System.Data.OleDb.OleDbCommand] CreateCommand([string]$Query) {
        $command = $this.Connection.CreateCommand()
        $command.CommandText = $Query
        return $command
    }

    [System.Data.DataTable] ExecuteQuery([string]$Query) {
        $dataTable = New-Object System.Data.DataTable

        try {
            $command = $this.CreateCommand($Query)
            $adapter = New-Object System.Data.OleDb.OleDbDataAdapter($command)
            $adapter.Fill($dataTable) | Out-Null
        }
        catch {
            throw "Query execution failed: $($_.Exception.Message)`nQuery: $Query"
        }

        return $dataTable
    }

    [int] ExecuteNonQuery([string]$Query) {
        try {
            $command = $this.CreateCommand($Query)
            return $command.ExecuteNonQuery()
        }
        catch {
            throw "Non-query execution failed: $($_.Exception.Message)`nQuery: $Query"
        }
    }

    [object] ExecuteScalar([string]$Query) {
        try {
            $command = $this.CreateCommand($Query)
            return $command.ExecuteScalar()
        }
        catch {
            throw "Scalar query execution failed: $($_.Exception.Message)`nQuery: $Query"
        }
    }
}

# ========================================
# CCI MAPPINGS OPERATIONS
# ========================================

function Get-CCIMappings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$false)]
        [string]$CCI_ID
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $query = @"
    SELECT CCI_ID, NIST_Controls, Control_Families, Description
    FROM CCI_Mappings
"@

    if ($CCI_ID) {
        $query += " WHERE CCI_ID = '$CCI_ID'"
    }

    $query += " ORDER BY CCI_ID"

    return $Connection.ExecuteQuery($query)
}

function Set-CCIMapping {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$true)]
        [string]$CCI_ID,

        [Parameter(Mandatory=$true)]
        [string[]]$NIST_Controls,

        [Parameter(Mandatory=$true)]
        [string[]]$Control_Families,

        [Parameter(Mandatory=$false)]
        [string]$Description
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $nistControlsStr = $NIST_Controls -join ', '
    $familiesStr = $Control_Families -join ', '

    $query = @"
    INSERT OR REPLACE INTO CCI_Mappings
    (CCI_ID, NIST_Controls, Control_Families, Description, Modified_Date)
    VALUES ('$CCI_ID', '$nistControlsStr', '$familiesStr', '$Description', NOW())
"@

    $Connection.ExecuteNonQuery($query) | Out-Null
    Write-Verbose "Updated CCI mapping for $CCI_ID"
}

function Import-CCIMappingsFromXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$true)]
        [string]$XmlPath
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    try {
        [xml]$cciXml = Get-Content -Path $XmlPath -Raw

        # Handle XML namespace
        $ns = New-Object System.Xml.XmlNamespaceManager($cciXml.NameTable)
        $ns.AddNamespace("cci", "http://iase.disa.mil/cci")

        $cciItems = $cciXml.SelectNodes("//cci:cci_item", $ns)
        $count = 0

        foreach ($cciItem in $cciItems) {
            $cciId = $cciItem.GetAttribute("id")
            $nistControls = @()

            $references = $cciItem.SelectNodes("cci:references/cci:reference", $ns)
            foreach ($reference in $references) {
                $title = $reference.GetAttribute("title")
                $index = $reference.GetAttribute("index")

                # Look for NIST 800-53 references
                if ($title -like '*800-53*' -and $index) {
                    $nistControls += $index
                }
            }

            if ($nistControls.Count -gt 0) {
                $families = @()
                foreach ($control in $nistControls) {
                    if ($control -match '^([A-Z]{2,3})-') {
                        $families += $matches[1]
                    }
                }

                Set-CCIMapping -Connection $Connection -CCI_ID $cciId `
                    -NIST_Controls $nistControls -Control_Families ($families | Select-Object -Unique) `
                    -Description "Imported from U_CCI_List.xml"
                $count++
            }
        }

        return $count
    }
    catch {
        throw "Failed to import CCI mappings: $($_.Exception.Message)"
    }
}

# ========================================
# STIG FILES OPERATIONS
# ========================================

function Get-STIGFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$false)]
        [int]$File_ID,

        [Parameter(Mandatory=$false)]
        [string]$File_Name
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $query = @"
    SELECT File_ID, File_Name, File_Path, File_Type, STIG_Title, STIG_Version,
           Release_Date, Import_Date, File_Size, Record_Count, Processing_Status
    FROM STIG_Files
"@

    $conditions = @()
    if ($File_ID) {
        $conditions += "File_ID = $File_ID"
    }
    if ($File_Name) {
        $conditions += "File_Name LIKE '%$File_Name%'"
    }

    if ($conditions.Count -gt 0) {
        $query += " WHERE " + ($conditions -join " AND ")
    }

    $query += " ORDER BY Import_Date DESC"

    return $Connection.ExecuteQuery($query)
}

function New-STIGFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$true)]
        [string]$File_Name,

        [Parameter(Mandatory=$true)]
        [string]$File_Path,

        [Parameter(Mandatory=$true)]
        [string]$File_Type,

        [Parameter(Mandatory=$true)]
        [string]$STIG_Title,

        [Parameter(Mandatory=$false)]
        [string]$STIG_Version,

        [Parameter(Mandatory=$false)]
        [datetime]$Release_Date,

        [Parameter(Mandatory=$false)]
        [long]$File_Size,

        [Parameter(Mandatory=$false)]
        [int]$Record_Count = 0
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $releaseDateStr = if ($Release_Date) { "'$($Release_Date.ToString('yyyy-MM-dd HH:mm:ss'))'" } else { "NULL" }
    $fileSizeStr = if ($File_Size) { $File_Size } else { "NULL" }

    $query = @"
    INSERT INTO STIG_Files
    (File_Name, File_Path, File_Type, STIG_Title, STIG_Version, Release_Date, File_Size, Record_Count)
    VALUES ('$File_Name', '$File_Path', '$File_Type', '$STIG_Title', '$STIG_Version', $releaseDateStr, $fileSizeStr, $Record_Count)
"@

    $Connection.ExecuteNonQuery($query) | Out-Null

    # Return the new File_ID
    $identityQuery = "SELECT @@IDENTITY"
    return $Connection.ExecuteScalar($identityQuery)
}

function Update-STIGFileStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$true)]
        [int]$File_ID,

        [Parameter(Mandatory=$true)]
        [string]$Status,

        [Parameter(Mandatory=$false)]
        [int]$Record_Count
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $setParts = @("Processing_Status = '$Status'")
    if ($Record_Count) {
        $setParts += "Record_Count = $Record_Count"
    }
    $setParts += "Modified_Date = NOW()"

    $query = @"
    UPDATE STIG_Files
    SET $($setParts -join ', ')
    WHERE File_ID = $File_ID
"@

    $Connection.ExecuteNonQuery($query) | Out-Null
}

# ========================================
# VULNERABILITIES OPERATIONS
# ========================================

function Get-Vulnerabilities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$false)]
        [int]$File_ID,

        [Parameter(Mandatory=$false)]
        [int]$Vulnerability_ID,

        [Parameter(Mandatory=$false)]
        [string]$Group_ID,

        [Parameter(Mandatory=$false)]
        [string]$Rule_ID,

        [Parameter(Mandatory=$false)]
        [string]$Severity,

        [Parameter(Mandatory=$false)]
        [string]$Status,

        [Parameter(Mandatory=$false)]
        [string]$NIST_Control,

        [Parameter(Mandatory=$false)]
        [string]$Control_Family,

        [Parameter(Mandatory=$false)]
        [int]$Limit = 1000
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $query = @"
    SELECT v.Vulnerability_ID, v.File_ID, v.Group_ID, v.Rule_ID, v.Rule_Version,
           v.Rule_Title, v.Severity, v.Status, v.STIG_Name, v.CCI_References,
           v.NIST_Controls, v.Control_Families, v.Discussion, v.Check_Content,
           v.Fix_Text, v.Finding_Details, v.Comments, v.Created_Date, v.Modified_Date,
           sf.File_Name, sf.STIG_Title
    FROM Vulnerabilities v
    INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID
"@

    $conditions = @()
    if ($File_ID) {
        $conditions += "v.File_ID = $File_ID"
    }
    if ($Vulnerability_ID) {
        $conditions += "v.Vulnerability_ID = $Vulnerability_ID"
    }
    if ($Group_ID) {
        $conditions += "v.Group_ID = '$Group_ID'"
    }
    if ($Rule_ID) {
        $conditions += "v.Rule_ID = '$Rule_ID'"
    }
    if ($Severity) {
        $conditions += "v.Severity = '$Severity'"
    }
    if ($Status) {
        $conditions += "v.Status = '$Status'"
    }
    if ($NIST_Control) {
        $conditions += "v.NIST_Controls LIKE '%$NIST_Control%'"
    }
    if ($Control_Family) {
        $conditions += "v.Control_Families LIKE '%$Control_Family%'"
    }

    if ($conditions.Count -gt 0) {
        $query += " WHERE " + ($conditions -join " AND ")
    }

    $query += " ORDER BY sf.File_Name, v.Group_ID"

    if ($Limit -and $Limit -gt 0) {
        $query += " LIMIT $Limit"
    }

    return $Connection.ExecuteQuery($query)
}

function New-Vulnerability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$true)]
        [int]$File_ID,

        [Parameter(Mandatory=$true)]
        [string]$Group_ID,

        [Parameter(Mandatory=$true)]
        [string]$Rule_ID,

        [Parameter(Mandatory=$true)]
        [string]$Rule_Version,

        [Parameter(Mandatory=$true)]
        [string]$Rule_Title,

        [Parameter(Mandatory=$true)]
        [string]$Severity,

        [Parameter(Mandatory=$true)]
        [string]$Status,

        [Parameter(Mandatory=$true)]
        [string]$STIG_Name,

        [Parameter(Mandatory=$true)]
        [string[]]$CCI_References,

        [Parameter(Mandatory=$true)]
        [string[]]$NIST_Controls,

        [Parameter(Mandatory=$true)]
        [string[]]$Control_Families,

        [Parameter(Mandatory=$false)]
        [string]$Discussion,

        [Parameter(Mandatory=$false)]
        [string]$Check_Content,

        [Parameter(Mandatory=$false)]
        [string]$Fix_Text,

        [Parameter(Mandatory=$false)]
        [string]$Finding_Details,

        [Parameter(Mandatory=$false)]
        [string]$Comments
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $cciStr = $CCI_References -join ', '
    $nistStr = $NIST_Controls -join ', '
    $familiesStr = $Control_Families -join ', '

    $query = @"
    INSERT INTO Vulnerabilities
    (File_ID, Group_ID, Rule_ID, Rule_Version, Rule_Title, Severity, Status, STIG_Name,
     CCI_References, NIST_Controls, Control_Families, Discussion, Check_Content, Fix_Text,
     Finding_Details, Comments)
    VALUES ($File_ID, '$Group_ID', '$Rule_ID', '$Rule_Version', '$Rule_Title', '$Severity',
            '$Status', '$STIG_Name', '$cciStr', '$nistStr', '$familiesStr',
            '$Discussion', '$Check_Content', '$Fix_Text', '$Finding_Details', '$Comments')
"@

    $Connection.ExecuteNonQuery($query) | Out-Null

    # Return the new Vulnerability_ID
    $identityQuery = "SELECT @@IDENTITY"
    return $Connection.ExecuteScalar($identityQuery)
}

function Update-Vulnerability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$true)]
        [int]$Vulnerability_ID,

        [Parameter(Mandatory=$false)]
        [string]$Status,

        [Parameter(Mandatory=$false)]
        [string]$Finding_Details,

        [Parameter(Mandatory=$false)]
        [string]$Comments
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $setParts = @("Modified_Date = NOW()")
    if ($Status) {
        $setParts += "Status = '$Status'"
    }
    if ($Finding_Details) {
        $setParts += "Finding_Details = '$Finding_Details'"
    }
    if ($Comments) {
        $setParts += "Comments = '$Comments'"
    }

    if ($setParts.Count -le 1) {
        return # No updates needed
    }

    $query = @"
    UPDATE Vulnerabilities
    SET $($setParts -join ', ')
    WHERE Vulnerability_ID = $Vulnerability_ID
"@

    $Connection.ExecuteNonQuery($query) | Out-Null
}

# ========================================
# ANALYSIS AND REPORTING OPERATIONS
# ========================================

function Get-DashboardSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $query = @"
    SELECT * FROM Dashboard_Summary
    ORDER BY File_Name
"@

    return $Connection.ExecuteQuery($query)
}

function Get-NISTFamilySummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $query = @"
    SELECT * FROM NIST_Family_Summary
    ORDER BY Family_Code
"@

    return $Connection.ExecuteQuery($query)
}

function Update-AnalysisResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$true)]
        [int]$File_ID
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    # Delete existing analysis results for this file
    $deleteQuery = "DELETE FROM Analysis_Results WHERE File_ID = $File_ID"
    $Connection.ExecuteNonQuery($deleteQuery) | Out-Null

    # Get family codes for analysis
    $familiesQuery = "SELECT Family_Code FROM NIST_Families"
    $families = $Connection.ExecuteQuery($familiesQuery)

    foreach ($row in $families.Rows) {
        $familyCode = $row.Family_Code

        # Get counts for this family
        $countsQuery = @"
        SELECT
            COUNT(*) as Total_Count,
            SUM(IIF(Status = 'Open', 1, 0)) as Open_Count,
            SUM(IIF(Status = 'NotAFinding' OR Status = 'Not_A_Finding', 1, 0)) as NotAFinding_Count,
            SUM(IIF(Status = 'Not_Reviewed', 1, 0)) as NotReviewed_Count,
            SUM(IIF(Severity = 'high' OR Severity = 'critical', 1, 0)) as High_Count,
            SUM(IIF(Severity = 'medium', 1, 0)) as Medium_Count,
            SUM(IIF(Severity = 'low', 1, 0)) as Low_Count
        FROM Vulnerabilities
        WHERE File_ID = $File_ID AND Control_Families LIKE '%$familyCode%'
"@

        $counts = $Connection.ExecuteQuery($countsQuery)
        if ($counts.Rows.Count -gt 0) {
            $total = $counts.Rows[0].Total_Count
            $compliant = $counts.Rows[0].NotAFinding_Count
            $compliance = if ($total -gt 0) { [math]::Round(($compliant / $total) * 100, 2) } else { 0 }

            $insertQuery = @"
            INSERT INTO Analysis_Results
            (File_ID, Control_Family, Analysis_Type, Total_Count, Open_Count, NotAFinding_Count,
             NotReviewed_Count, High_Count, Medium_Count, Low_Count, Compliance_Percentage)
            VALUES ($File_ID, '$familyCode', 'Compliance', $($counts.Rows[0].Total_Count),
                    $($counts.Rows[0].Open_Count), $($counts.Rows[0].NotAFinding_Count),
                    $($counts.Rows[0].NotReviewed_Count), $($counts.Rows[0].High_Count),
                    $($counts.Rows[0].Medium_Count), $($counts.Rows[0].Low_Count), $compliance)
"@

            $Connection.ExecuteNonQuery($insertQuery) | Out-Null
        }
    }

    Write-Verbose "Updated analysis results for File_ID $File_ID"
}

# ========================================
# EXPORT OPERATIONS
# ========================================

function Log-Export {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$true)]
        [string]$Export_Type,

        [Parameter(Mandatory=$true)]
        [string]$File_Path,

        [Parameter(Mandatory=$true)]
        [int]$Record_Count,

        [Parameter(Mandatory=$true)]
        [string]$Status,

        [Parameter(Mandatory=$false)]
        [string]$Error_Message
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $query = @"
    INSERT INTO Export_History
    (Export_Type, File_Path, Record_Count, Export_Status, Error_Message)
    VALUES ('$Export_Type', '$File_Path', $Record_Count, '$Status', '$Error_Message')
"@

    $Connection.ExecuteNonQuery($query) | Out-Null
}

# ========================================
# UTILITY FUNCTIONS
# ========================================

function Test-DatabaseConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DatabasePath
    )

    try {
        $connection = [DatabaseConnection]::new($DatabasePath)
        $connected = $connection.Connect()

        if ($connected) {
            # Test with a simple query
            $result = $connection.ExecuteQuery("SELECT COUNT(*) as Count FROM CCI_Mappings")
            $connection.Disconnect()
            return $true
        }

        return $false
    }
    catch {
        Write-Warning "Database connection test failed: $($_.Exception.Message)"
        return $false
    }
}

function Initialize-Database {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DatabasePath,

        [Parameter(Mandatory=$false)]
        [string]$SchemaPath
    )

    # Check if database exists
    if (Test-Path $DatabasePath) {
        Write-Verbose "Database already exists at $DatabasePath"
        return $true
    }

    # Create new database
    try {
        $catalog = New-Object -ComObject ADOX.Catalog
        $catalog.Create("Provider=Microsoft.ACE.OLEDB.16.0;Data Source=$DatabasePath")

        if ($SchemaPath -and (Test-Path $SchemaPath)) {
            Write-Verbose "Applying schema from $SchemaPath"

            # Read and execute schema SQL
            $schemaSql = Get-Content -Path $SchemaPath -Raw

            $connection = [DatabaseConnection]::new($DatabasePath)
            $connection.Connect()

            # Split by semicolon and execute each statement
            $statements = $schemaSql -split ';' | Where-Object { $_.Trim() -ne '' }

            foreach ($statement in $statements) {
                if ($statement.Trim() -ne '') {
                    try {
                        $connection.ExecuteNonQuery($statement.Trim()) | Out-Null
                    }
                    catch {
                        Write-Warning "Failed to execute schema statement: $($_.Exception.Message)"
                    }
                }
            }

            $connection.Disconnect()
        }

        Write-Verbose "Database initialized successfully at $DatabasePath"
        return $true
    }
    catch {
        throw "Failed to initialize database: $($_.Exception.Message)"
    }
}

# Export module functions
Export-ModuleMember -Function @(
    'Get-CCIMappings',
    'Set-CCIMapping',
    'Import-CCIMappingsFromXml',
    'Get-STIGFiles',
    'New-STIGFile',
    'Update-STIGFileStatus',
    'Get-Vulnerabilities',
    'New-Vulnerability',
    'Update-Vulnerability',
    'Get-DashboardSummary',
    'Get-NISTFamilySummary',
    'Update-AnalysisResults',
    'Log-Export',
    'Test-DatabaseConnection',
    'Initialize-Database'
)

# Export classes
Export-ModuleMember -Class @('DatabaseConnection')
