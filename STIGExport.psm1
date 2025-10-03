<#
.SYNOPSIS
    STIG Export Module for Database Edition

.DESCRIPTION
    This module provides enhanced Excel export capabilities for STIG analysis data from MS Access 2016 database.
    Includes professional formatting, multiple sheets, charts, and advanced features.

.NOTES
    Requirements: Microsoft Office 2016+, STIG Database Module
    Version: 2.0
    Author: STIG Analysis Tool Team
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

# Add required assemblies
Add-Type -AssemblyName System.Windows.Forms

# Import database module
Import-Module .\STIGDatabase.psm1 -Force

# ========================================
# EXCEL EXPORT FUNCTIONS
# ========================================

function Export-STIGDataToExcel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [Parameter(Mandatory=$false)]
        [System.Windows.Forms.Label]$StatusLabel = $null,

        [Parameter(Mandatory=$false)]
        [System.Windows.Forms.ProgressBar]$ProgressBar = $null,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeCharts = $true,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeNISTSheets = $true
    )

    $excel = $null
    $workbook = $null
    $dashboardSheet = $null
    $sheets = @()

    try {
        # Progress tracking setup
        $totalSteps = 7  # Initialize, Group Data, Create Excel, Create Sheets, Create Dashboard, Charts, Save
        $currentStep = 0

        # Step 1: Initialize
        $currentStep++
        if ($StatusLabel) {
            $StatusLabel.Text = "Step 1/$totalSteps" + ": Initializing Excel (0%)..."
            [System.Windows.Forms.Application]::DoEvents()
        }
        if ($ProgressBar) {
            $ProgressBar.Style = 'Continuous'
            $ProgressBar.Minimum = 0
            $ProgressBar.Maximum = 100
            $ProgressBar.Value = 0
        }

        # Create Excel COM object
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $excel.DisplayAlerts = $false

        # Create workbook
        $workbook = $excel.Workbooks.Add()

        # Set performance optimizations
        $excel.ScreenUpdating = $false
        try {
            $excel.Calculation = -4135  # xlCalculationManual
        } catch {
            Write-Verbose "Could not set manual calculation: $_"
        }

        if ($ProgressBar) {
            $ProgressBar.Value = 10
        }

        # Step 2: Get and prepare data
        $currentStep++
        if ($StatusLabel) {
            $StatusLabel.Text = "Step 2/$totalSteps" + ": Retrieving data from database (10%)..."
            [System.Windows.Forms.Application]::DoEvents()
        }

        # Get all STIG files and vulnerabilities
        $stigFiles = Get-STIGFiles -Connection $Connection
        $vulnerabilities = Get-Vulnerabilities -Connection $Connection -Limit 50000

        if ($ProgressBar) {
            $ProgressBar.Value = 20
        }

        # Group vulnerabilities by STIG file
        $stigGroups = $vulnerabilities.Rows | Group-Object -Property File_Name

        if ($ProgressBar) {
            $ProgressBar.Value = 30
        }

        Write-Verbose "Creating $($stigGroups.Count) STIG sheets..."

        # Define headers for STIG sheets
        $headers = @(
            'NIST Controls', 'NIST Family', 'CCIs', 'Vuln-ID', 'Rule-ID',
            'Rule Version', 'Title', 'Severity', 'Status', 'STIG Name',
            'Discussion', 'Check Content', 'Fix Text', 'Finding Details',
            'Comments', 'Source File'
        )

        # Create STIG sheets
        $sheetIndex = 0
        foreach ($stigGroup in $stigGroups) {
            $sheetIndex++
            $stigFileName = $stigGroup.Name -replace '\.(ckl|cklb)$', ''
            $stigFileName = $stigFileName -replace '[:\\\/\[\]\*\?<\>\|\-]', '_'
            if ($stigFileName.Length -gt 31) { $stigFileName = $stigFileName.Substring(0, 31) }

            # Update progress
            $sheetProgress = [int](30 + (($sheetIndex / $stigGroups.Count) * 40))
            if ($StatusLabel) {
                $StatusLabel.Text = "Creating sheet $sheetIndex of $($stigGroups.Count): $stigFileName ($sheetProgress%)..."
                [System.Windows.Forms.Application]::DoEvents()
            }
            if ($ProgressBar) {
                $ProgressBar.Value = $sheetProgress
                [System.Windows.Forms.Application]::DoEvents()
            }

            Write-Verbose "Creating sheet $sheetIndex of $($stigGroups.Count): $stigFileName"
            $sheet = New-STIGSheet -Workbook $workbook -SheetName $stigFileName -Vulnerabilities $stigGroup.Group -Headers $headers
            $sheets += $sheet
        }

        # Step 4: Create Dashboard
        if ($StatusLabel) {
            $StatusLabel.Text = "Step 4/$totalSteps" + ": Creating Dashboard (75%)..."
            [System.Windows.Forms.Application]::DoEvents()
        }
        if ($ProgressBar) {
            $ProgressBar.Value = 75
            [System.Windows.Forms.Application]::DoEvents()
        }

        Write-Verbose "Creating Dashboard sheet..."
        $dashboardSheet = $workbook.Worksheets.Add($workbook.Worksheets.Item(1))
        $dashboardSheet.Name = "Dashboard"

        # Remove default Sheet1 if it exists
        if ($sheets.Count -gt 0) {
            try {
                for ($i = 1; $i -le $workbook.Worksheets.Count; $i++) {
                    if ($workbook.Worksheets.Item($i).Name -eq "Sheet1") {
                        $workbook.Worksheets.Item($i).Delete()
                        break
                    }
                }
            } catch {
                Write-Verbose "Could not delete default sheet: $_"
            }
        }

        # Create enhanced dashboard
        New-EnhancedDashboard -Workbook $workbook -DashboardSheet $dashboardSheet -Vulnerabilities $vulnerabilities.Rows -StigFiles $stigFiles.Rows

        # Step 5: Create NIST Control sheets (if requested)
        if ($IncludeNISTSheets) {
            if ($StatusLabel) {
                $StatusLabel.Text = "Step 5/$totalSteps" + ": Creating NIST Control sheets (85%)..."
                [System.Windows.Forms.Application]::DoEvents()
            }
            if ($ProgressBar) {
                $ProgressBar.Value = 85
                [System.Windows.Forms.Application]::DoEvents()
            }

            try {
                New-NISTControlSheets -Workbook $workbook -InsertAfterSheet $dashboardSheet -Connection $Connection
            } catch {
                Write-Verbose "Warning: Could not create NIST Control sheets: $_"
            }
        }

        # Step 6: Create Charts (if requested)
        if ($IncludeCharts) {
            if ($StatusLabel) {
                $StatusLabel.Text = "Step 6/$totalSteps" + ": Creating charts (90%)..."
                [System.Windows.Forms.Application]::DoEvents()
            }
            if ($ProgressBar) {
                $ProgressBar.Value = 90
                [System.Windows.Forms.Application]::DoEvents()
            }

            try {
                New-DashboardCharts -Workbook $workbook -DashboardSheet $dashboardSheet -Vulnerabilities $vulnerabilities.Rows
            } catch {
                Write-Verbose "Warning: Could not create charts: $_"
            }
        }

        # Step 7: Save workbook
        if ($StatusLabel) {
            $StatusLabel.Text = "Step 7/$totalSteps" + ": Saving workbook (95%)..."
            [System.Windows.Forms.Application]::DoEvents()
        }
        if ($ProgressBar) {
            $ProgressBar.Value = 95
            [System.Windows.Forms.Application]::DoEvents()
        }

        if (-not $workbook) {
            throw "Workbook object is null"
        }

        if (Test-Path $OutputPath) {
            Remove-Item -Path $OutputPath -Force
        }

        # Re-enable calculation and screen updating before save
        try {
            $excel.Calculation = -4105  # xlCalculationAutomatic
        } catch {
            Write-Verbose "Could not set automatic calculation: $_"
        }
        $excel.ScreenUpdating = $true

        # Convert to full path for Excel
        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

        $workbook.SaveAs($fullPath, 51)  # xlOpenXMLWorkbook

        if ($ProgressBar) {
            $ProgressBar.Value = 100
        }
        if ($StatusLabel) {
            $StatusLabel.Text = "Export complete (100%)!"
            [System.Windows.Forms.Application]::DoEvents()
        }

        $workbook.Close($false)

        # Log export
        try {
            Log-Export -Connection $Connection -Export_Type "Excel" -File_Path $OutputPath `
                -Record_Count $vulnerabilities.Rows.Count -Status "Success"
        } catch {
            Write-Verbose "Could not log export: $_"
        }

        return @{
            Success = $true
            Path = $OutputPath
            VulnerabilitiesExported = $vulnerabilities.Rows.Count
            StigFilesExported = $stigFiles.Rows.Count
        }
    }
    catch {
        # Log export failure
        try {
            Log-Export -Connection $Connection -Export_Type "Excel" -File_Path $OutputPath `
                -Record_Count 0 -Status "Failed" -Error_Message $_.Exception.Message
        } catch {
            Write-Verbose "Could not log export failure: $_"
        }

        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
    finally {
        # Clean up COM objects in proper order
        if ($dashboardSheet) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($dashboardSheet) } catch {}
            $dashboardSheet = $null
        }
        if ($sheets -and $sheets.Count -gt 0) {
            foreach ($sheet in $sheets) {
                try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($sheet) } catch {}
            }
            $sheets = @()
        }
        if ($workbook) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($workbook) } catch {}
            $workbook = $null
        }
        if ($excel) {
            try {
                $excel.Quit()
                Start-Sleep -Milliseconds 100
            } catch {}
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) } catch {}
            $excel = $null
        }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
    }
}

function New-STIGSheet {
    param(
        [Parameter(Mandatory)]$Workbook,
        [Parameter(Mandatory)][string]$SheetName,
        [Parameter(Mandatory)][array]$Vulnerabilities,
        [Parameter(Mandatory)][array]$Headers
    )

    $worksheet = $Workbook.Worksheets.Add()
    $worksheet.Name = $SheetName

    # Write headers
    for ($col = 1; $col -le $Headers.Count; $col++) {
        $worksheet.Cells.Item(1, $col) = $Headers[$col - 1]
    }

    # Write data
    $row = 2
    foreach ($v in $Vulnerabilities) {
        $worksheet.Cells.Item($row, 1) = ($v.NIST_Controls -join ', ')
        $worksheet.Cells.Item($row, 2) = ($v.Control_Families -join ', ')
        $worksheet.Cells.Item($row, 3) = ($v.CCI_References -join ', ')
        $worksheet.Cells.Item($row, 4) = $v.Group_ID
        $worksheet.Cells.Item($row, 5) = $v.Rule_ID
        $worksheet.Cells.Item($row, 6) = $v.Rule_Version
        $worksheet.Cells.Item($row, 7) = $v.Rule_Title
        $worksheet.Cells.Item($row, 8) = $v.Severity
        $worksheet.Cells.Item($row, 9) = $v.Status
        $worksheet.Cells.Item($row, 10) = $v.STIG_Name
        $worksheet.Cells.Item($row, 11) = $v.Discussion
        $worksheet.Cells.Item($row, 12) = $v.Check_Content
        $worksheet.Cells.Item($row, 13) = $v.Fix_Text
        $worksheet.Cells.Item($row, 14) = $v.Finding_Details
        $worksheet.Cells.Item($row, 15) = $v.Comments
        $worksheet.Cells.Item($row, 16) = $v.File_Name
        $row++
    }

    # Create Excel Table and apply formatting
    if ($row -gt 2) {
        try {
            # Create table range
            $tableRange = $worksheet.Range($worksheet.Cells.Item(1, 1), $worksheet.Cells.Item($row - 1, $Headers.Count))

            # Create ListObject (Excel Table)
            $tableName = "STIG_$($SheetName -replace '[^a-zA-Z0-9]', '_')"
            $listObject = $worksheet.ListObjects.Add(1, $tableRange, $null, 1)
            $listObject.Name = $tableName
            $listObject.TableStyle = "TableStyleMedium2"

            # Optimize column widths and row heights
            $tableRange.EntireColumn.AutoFit() | Out-Null

            for ($col = 1; $col -le $Headers.Count; $col++) {
                $colWidth = $worksheet.Columns.Item($col).ColumnWidth
                if ($col -ge 11) {
                    if ($colWidth -gt 80) { $worksheet.Columns.Item($col).ColumnWidth = 80 }
                } elseif ($colWidth -gt 50) {
                    $worksheet.Columns.Item($col).ColumnWidth = 50
                }
            }

            # Apply text formatting - wrap text and top align
            $tableRange.WrapText = $true
            $tableRange.VerticalAlignment = -4160  # xlTop

            # Auto-fit row heights after wrapping
            $dataRange = $worksheet.Range($worksheet.Cells.Item(2, 1), $worksheet.Cells.Item($row - 1, $Headers.Count))
            $dataRange.EntireRow.AutoFit() | Out-Null

            # Apply conditional formatting
            $severityCol = 8
            $severityRange = $worksheet.Range($worksheet.Cells.Item(2, $severityCol), $worksheet.Cells.Item($row - 1, $severityCol))

            $highCond = $severityRange.FormatConditions.Add(1, 3, "=LOWER(H2)=`"high`"")
            $highCond.Interior.Color = 0x6060FF
            $highCond.Font.Color = 0x000080
            $highCond.Font.Bold = $true

            $critCond = $severityRange.FormatConditions.Add(1, 3, "=LOWER(H2)=`"critical`"")
            $critCond.Interior.Color = 0x4040FF
            $critCond.Font.Color = 0xFFFFFF
            $critCond.Font.Bold = $true

            $medCond = $severityRange.FormatConditions.Add(1, 3, "=LOWER(H2)=`"medium`"")
            $medCond.Interior.Color = 0x99FFFF
            $medCond.Font.Color = 0x006600

            $lowCond = $severityRange.FormatConditions.Add(1, 3, "=LOWER(H2)=`"low`"")
            $lowCond.Interior.Color = 0x90EE90
            $lowCond.Font.Color = 0x006400

            $statusCol = 9
            $statusRange = $worksheet.Range($worksheet.Cells.Item(2, $statusCol), $worksheet.Cells.Item($row - 1, $statusCol))

            $openCond = $statusRange.FormatConditions.Add(1, 3, "=I2=`"Open`"")
            $openCond.Interior.Color = 0x6060FF
            $openCond.Font.Color = 0x000080
            $openCond.Font.Bold = $true

            $nafCond = $statusRange.FormatConditions.Add(1, 3, "=I2=`"NotAFinding`"")
            $nafCond.Interior.Color = 0x90EE90
            $nafCond.Font.Color = 0x006400

            $nrCond = $statusRange.FormatConditions.Add(1, 3, "=I2=`"Not_Reviewed`"")
            $nrCond.Interior.Color = 0xCCFFFF
            $nrCond.Font.Color = 0x996600

            $naCond = $statusRange.FormatConditions.Add(1, 3, "=I2=`"NotApplicable`"")
            $naCond.Interior.Color = 0xD3D3D3
            $naCond.Font.Color = 0x505050

        } catch {
            Write-Verbose "Warning: Could not create table or apply formatting: $_"
        }

        # Freeze top row
        try {
            $worksheet.Application.ActiveWindow.SplitRow = 1
            $worksheet.Application.ActiveWindow.FreezePanes = $true
        } catch {
            Write-Verbose "Warning: Could not freeze panes: $_"
        }
    }

    return $worksheet
}

function New-EnhancedDashboard {
    param(
        [Parameter(Mandatory)]$Workbook,
        [Parameter(Mandatory)]$DashboardSheet,
        [Parameter(Mandatory)]$Vulnerabilities,
        [Parameter(Mandatory)]$StigFiles
    )

    # Dashboard Title - Row 1
    $DashboardSheet.Cells.Item(1, 1) = "STIG NIST Mapping - Compliance Dashboard (Database Edition)"
    $DashboardSheet.Cells.Item(1, 1).Font.Size = 18
    $DashboardSheet.Cells.Item(1, 1).Font.Bold = $true
    $DashboardSheet.Cells.Item(1, 1).Font.Color = 0xFFFFFF
    $titleRange = $DashboardSheet.Range("A1:L1")
    $titleRange.Merge() | Out-Null
    $titleRange.Interior.Color = 0x0070C0
    $titleRange.HorizontalAlignment = -4108  # xlCenter
    $titleRange.VerticalAlignment = -4108
    $DashboardSheet.Rows.Item(1).RowHeight = 35

    # Summary Cards - Row 3-6
    $row = 3

    # Calculate summary statistics
    $totalFindings = $Vulnerabilities.Count
    $openFindings = ($Vulnerabilities | Where-Object { $_.Status -eq 'Open' }).Count
    $notAFinding = ($Vulnerabilities | Where-Object { $_.Status -eq 'NotAFinding' -or $_.Status -eq 'Not_A_Finding' }).Count
    $notReviewed = ($Vulnerabilities | Where-Object { $_.Status -eq 'Not_Reviewed' }).Count
    $highSeverity = ($Vulnerabilities | Where-Object { $_.Severity -eq 'high' -or $_.Severity -eq 'critical' }).Count
    $mediumSeverity = ($Vulnerabilities | Where-Object { $_.Severity -eq 'medium' }).Count
    $lowSeverity = ($Vulnerabilities | Where-Object { $_.Severity -eq 'low' }).Count

    $complianceRate = if ($totalFindings -gt 0) { [math]::Round(($notAFinding / $totalFindings) * 100, 2) } else { 0 }

    # Summary Cards
    $cards = @(
        @{Label="Total STIG Files"; Value=$StigFiles.Count; Color=0x0070C0},
        @{Label="Total Findings"; Value=$totalFindings; Color=0x0070C0},
        @{Label="Open Findings"; Value=$openFindings; Color=0xFF6B6B},
        @{Label="Compliance Rate"; Value="$complianceRate%"; Color=0x51CF66},
        @{Label="High Severity"; Value=$highSeverity; Color=0xFF6B6B},
        @{Label="Medium Severity"; Value=$mediumSeverity; Color=0xFFD93D},
        @{Label="Low Severity"; Value=$lowSeverity; Color=0x51CF66},
        @{Label="Not Reviewed"; Value=$notReviewed; Color=0x6C757D}
    )

    for ($i = 0; $i -lt $cards.Count; $i++) {
        $col = ($i % 4) * 3 + 1
        $cardRow = $row + [math]::Floor($i / 4) * 4

        # Card background
        $cardRange = $DashboardSheet.Range($DashboardSheet.Cells.Item($cardRow, $col), $DashboardSheet.Cells.Item($cardRow + 2, $col + 2))
        $cardRange.Interior.Color = $cards[$i].Color
        $cardRange.Font.Color = 0xFFFFFF

        # Label
        $DashboardSheet.Cells.Item($cardRow, $col) = $cards[$i].Label
        $DashboardSheet.Cells.Item($cardRow, $col).Font.Bold = $true

        # Value
        $DashboardSheet.Cells.Item($cardRow + 1, $col) = $cards[$i].Value
        $DashboardSheet.Cells.Item($cardRow + 1, $col).Font.Size = 24
        $DashboardSheet.Cells.Item($cardRow + 1, $col).Font.Bold = $true

        # Merge cells for card
        $cardRange.Merge() | Out-Null
        $cardRange.HorizontalAlignment = -4108  # xlCenter
        $cardRange.VerticalAlignment = -4108
    }

    # System Summary Table - Row 12+
    $row = 12
    $DashboardSheet.Cells.Item($row, 1) = "System Summary"
    $DashboardSheet.Cells.Item($row, 1).Font.Bold = $true
    $DashboardSheet.Cells.Item($row, 1).Font.Size = 14
    $row++

    # Headers
    $headers = @("System Name", "Total Findings", "Open", "Not a Finding", "Not Reviewed", "High", "Medium", "Low", "Compliance %")
    for ($col = 1; $col -le $headers.Count; $col++) {
        $DashboardSheet.Cells.Item($row, $col) = $headers[$col - 1]
        $DashboardSheet.Cells.Item($row, $col).Font.Bold = $true
        $DashboardSheet.Cells.Item($row, $col).Interior.Color = 0xD9E1F2
        $DashboardSheet.Cells.Item($row, $col).HorizontalAlignment = -4108
    }
    $row++

    # System data
    $systemIndex = 0
    foreach ($stigFile in $StigFiles) {
        if ($systemIndex -ge 20) { break }  # Limit to 20 systems

        $fileVulns = $Vulnerabilities | Where-Object { $_.File_ID -eq $stigFile.File_ID }

        $systemFindings = $fileVulns.Count
        $systemOpen = ($fileVulns | Where-Object { $_.Status -eq 'Open' }).Count
        $systemNotAFinding = ($fileVulns | Where-Object { $_.Status -eq 'NotAFinding' -or $_.Status -eq 'Not_A_Finding' }).Count
        $systemNotReviewed = ($fileVulns | Where-Object { $_.Status -eq 'Not_Reviewed' }).Count
        $systemHigh = ($fileVulns | Where-Object { $_.Severity -eq 'high' -or $_.Severity -eq 'critical' }).Count
        $systemMedium = ($fileVulns | Where-Object { $_.Severity -eq 'medium' }).Count
        $systemLow = ($fileVulns | Where-Object { $_.Severity -eq 'low' }).Count

        $systemCompliance = if ($systemFindings -gt 0) { [math]::Round(($systemNotAFinding / $systemFindings) * 100, 1) } else { 0 }

        $DashboardSheet.Cells.Item($row, 1) = $stigFile.STIG_Title
        $DashboardSheet.Cells.Item($row, 2) = $systemFindings
        $DashboardSheet.Cells.Item($row, 3) = $systemOpen
        $DashboardSheet.Cells.Item($row, 4) = $systemNotAFinding
        $DashboardSheet.Cells.Item($row, 5) = $systemNotReviewed
        $DashboardSheet.Cells.Item($row, 6) = $systemHigh
        $DashboardSheet.Cells.Item($row, 7) = $systemMedium
        $DashboardSheet.Cells.Item($row, 8) = $systemLow
        $DashboardSheet.Cells.Item($row, 9).Formula = "=IF(B$row>0,ROUND((D$row/B$row)*100,1),0)"
        $DashboardSheet.Cells.Item($row, 9).NumberFormat = "0.0%"

        $row++
        $systemIndex++
    }

    # Format columns
    $DashboardSheet.Columns.Item(1).ColumnWidth = 35  # System Name
    $DashboardSheet.Columns.Item(2).ColumnWidth = 14  # Total Findings
    $DashboardSheet.Columns.Item(3).ColumnWidth = 10  # Open
    $DashboardSheet.Columns.Item(4).ColumnWidth = 14  # Not a Finding
    $DashboardSheet.Columns.Item(5).ColumnWidth = 13  # Not Reviewed
    $DashboardSheet.Columns.Item(6).ColumnWidth = 10  # High
    $DashboardSheet.Columns.Item(7).ColumnWidth = 10  # Medium
    $DashboardSheet.Columns.Item(8).ColumnWidth = 10  # Low
    $DashboardSheet.Columns.Item(9).ColumnWidth = 13  # Compliance %
}

function New-NISTControlSheets {
    param(
        [Parameter(Mandatory)]$Workbook,
        [Parameter(Mandatory)]$InsertAfterSheet,
        [Parameter(Mandatory)]$Connection
    )

    # Get NIST family summary from database
    $nistSummary = Get-NISTFamilySummary -Connection $Connection

    # Create Compliance Summary sheet
    $complianceSheet = $Workbook.Worksheets.Add()
    $complianceSheet.Name = "Compliance Summary"
    $complianceSheet.Move($null, $InsertAfterSheet)

    # Title
    $complianceSheet.Cells.Item(1, 1) = "NIST 800-53 Control Family Compliance Summary"
    $complianceSheet.Cells.Item(1, 1).Font.Size = 16
    $complianceSheet.Cells.Item(1, 1).Font.Bold = $true
    $titleRange = $complianceSheet.Range("A1:J1")
    $titleRange.Merge() | Out-Null
    $titleRange.HorizontalAlignment = -4108

    # Headers
    $headers = @('Control Family', 'Family Name', 'Total Vulnerabilities', 'Open', 'Compliant', 'Not Reviewed', 'High', 'Medium', 'Low', 'Compliance %')
    for ($col = 1; $col -le $headers.Count; $col++) {
        $complianceSheet.Cells.Item(3, $col) = $headers[$col - 1]
        $complianceSheet.Cells.Item(3, $col).Font.Bold = $true
        $complianceSheet.Cells.Item(3, $col).Interior.Color = 0xD9E1F2
    }

    # Data
    $row = 4
    foreach ($family in $nistSummary.Rows) {
        $complianceSheet.Cells.Item($row, 1) = $family.Family_Code
        $complianceSheet.Cells.Item($row, 2) = $family.Family_Name
        $complianceSheet.Cells.Item($row, 3) = $family.Vulnerability_Count
        $complianceSheet.Cells.Item($row, 4) = $family.Open_Count
        $complianceSheet.Cells.Item($row, 5) = $family.Compliant_Count
        $complianceSheet.Cells.Item($row, 6) = $family.Vulnerability_Count - $family.Open_Count - $family.Compliant_Count
        $complianceSheet.Cells.Item($row, 7) = 0  # Would need to calculate from detailed data
        $complianceSheet.Cells.Item($row, 8) = 0
        $complianceSheet.Cells.Item($row, 9) = 0
        $complianceSheet.Cells.Item($row, 10).Formula = "=IF(C$row>0,E$row/C$row,0)"
        $complianceSheet.Cells.Item($row, 10).NumberFormat = "0.0%"

        $row++
    }

    # Format table
    $tableRange = $complianceSheet.Range($complianceSheet.Cells.Item(3, 1), $complianceSheet.Cells.Item($row - 1, 10))
    $tableRange.EntireColumn.AutoFit() | Out-Null

    # Create table
    try {
        $listObject = $complianceSheet.ListObjects.Add(1, $tableRange, $null, 1)
        $listObject.Name = "ComplianceSummary"
        $listObject.TableStyle = "TableStyleMedium2"
    } catch {
        Write-Verbose "Could not create compliance table: $_"
    }
}

function New-DashboardCharts {
    param(
        [Parameter(Mandatory)]$Workbook,
        [Parameter(Mandatory)]$DashboardSheet,
        [Parameter(Mandatory)]$Vulnerabilities
    )

    try {
        # Chart 1: Status Distribution (Pie Chart)
        $chart1 = $DashboardSheet.ChartObjects().Add(500, 100, 400, 300)
        $chart1.Chart.ChartType = 5  # xlPie

        # Count statuses
        $statusCounts = @{}
        foreach ($vuln in $Vulnerabilities) {
            $status = $vuln.Status
            if ($statusCounts.ContainsKey($status)) {
                $statusCounts[$status]++
            } else {
                $statusCounts[$status] = 1
            }
        }

        # Create data range for chart
        $chartDataRow = 20
        $DashboardSheet.Cells.Item($chartDataRow, 1) = "Status"
        $DashboardSheet.Cells.Item($chartDataRow, 2) = "Count"
        $chartDataRow++

        foreach ($status in $statusCounts.Keys) {
            $DashboardSheet.Cells.Item($chartDataRow, 1) = $status
            $DashboardSheet.Cells.Item($chartDataRow, 2) = $statusCounts[$status]
            $chartDataRow++
        }

        $dataRange = $DashboardSheet.Range($DashboardSheet.Cells.Item(21, 1), $DashboardSheet.Cells.Item($chartDataRow - 1, 2))
        $chart1.Chart.SetSourceData($dataRange)
        $chart1.Chart.HasTitle = $true
        $chart1.Chart.ChartTitle.Text = "Status Distribution"
        $chart1.Chart.HasLegend = $true

        # Chart 2: Severity Distribution (Column Chart)
        $chart2 = $DashboardSheet.ChartObjects().Add(500, 450, 400, 300)
        $chart2.Chart.ChartType = 51  # xlColumnClustered

        # Count severities
        $severityCounts = @{}
        foreach ($vuln in $Vulnerabilities) {
            $severity = $vuln.Severity
            if ($severityCounts.ContainsKey($severity)) {
                $severityCounts[$severity]++
            } else {
                $severityCounts[$severity] = 1
            }
        }

        $chartDataRow = 20
        $DashboardSheet.Cells.Item($chartDataRow, 4) = "Severity"
        $DashboardSheet.Cells.Item($chartDataRow, 5) = "Count"
        $chartDataRow++

        foreach ($severity in $severityCounts.Keys) {
            $DashboardSheet.Cells.Item($chartDataRow, 4) = $severity
            $DashboardSheet.Cells.Item($chartDataRow, 5) = $severityCounts[$severity]
            $chartDataRow++
        }

        $dataRange = $DashboardSheet.Range($DashboardSheet.Cells.Item(21, 4), $DashboardSheet.Cells.Item($chartDataRow - 1, 5))
        $chart2.Chart.SetSourceData($dataRange)
        $chart2.Chart.HasTitle = $true
        $chart2.Chart.ChartTitle.Text = "Severity Distribution"
        $chart2.Chart.HasLegend = $true

    } catch {
        Write-Verbose "Warning: Could not create dashboard charts: $_"
    }
}

# Export module functions
Export-ModuleMember -Function @(
    'Export-STIGDataToExcel',
    'New-STIGSheet',
    'New-EnhancedDashboard',
    'New-NISTControlSheets',
    'New-DashboardCharts'
)
