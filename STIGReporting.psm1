<#
.SYNOPSIS
    STIG Advanced Reporting and Search Module

.DESCRIPTION
    This module provides advanced search, filtering, and reporting capabilities for STIG analysis data
    using sophisticated database queries and PowerShell-based analytics.

.NOTES
    Requirements: STIG Database Module, PowerShell 5.1+
    Features: Advanced filtering, Custom reports, Trend analysis, Compliance scoring
    Version: 2.0
    Author: STIG Analysis Tool Team
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

# Import database module
Import-Module .\STIGDatabase.psm1 -Force

# ========================================
# ADVANCED SEARCH AND FILTERING
# ========================================

function Search-Vulnerabilities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$false)]
        [string]$SearchTerm,

        [Parameter(Mandatory=$false)]
        [string]$StigFile,

        [Parameter(Mandatory=$false)]
        [string[]]$Severities = @(),

        [Parameter(Mandatory=$false)]
        [string[]]$Statuses = @(),

        [Parameter(Mandatory=$false)]
        [string[]]$NISTControls = @(),

        [Parameter(Mandatory=$false)]
        [string[]]$ControlFamilies = @(),

        [Parameter(Mandatory=$false)]
        [string[]]$CCIReferences = @(),

        [Parameter(Mandatory=$false)]
        [switch]$IncludeDetails = $true,

        [Parameter(Mandatory=$false)]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false)]
        [switch]$ExportToCsv,

        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $query = @"
    SELECT $(if ($IncludeDetails) { "v.*" } else { "v.Vulnerability_ID, v.Group_ID, v.Rule_ID, v.Rule_Title, v.Severity, v.Status, v.STIG_Name" }),
           sf.File_Name, sf.STIG_Title
    FROM Vulnerabilities v
    INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID
"@

    $conditions = @()

    # Build WHERE conditions
    if ($SearchTerm) {
        $searchConditions = @(
            "v.Rule_Title LIKE '%$SearchTerm%'",
            "v.Group_ID LIKE '%$SearchTerm%'",
            "v.Rule_ID LIKE '%$SearchTerm%'",
            "v.Discussion LIKE '%$SearchTerm%'",
            "v.Check_Content LIKE '%$SearchTerm%'"
        )
        $conditions += "($(($searchConditions -join " OR ")))"
    }

    if ($StigFile) {
        $conditions += "sf.File_Name LIKE '%$StigFile%'"
    }

    if ($Severities.Count -gt 0) {
        $severityList = $Severities | ForEach-Object { "'$_'" } | Join-String -Separator ', '
        $conditions += "v.Severity IN ($severityList)"
    }

    if ($Statuses.Count -gt 0) {
        $statusList = $Statuses | ForEach-Object { "'$_'" } | Join-String -Separator ', '
        $conditions += "v.Status IN ($statusList)"
    }

    if ($NISTControls.Count -gt 0) {
        $nistConditions = $NISTControls | ForEach-Object {
            "v.NIST_Controls LIKE '%$_%'"
        }
        $conditions += "($(($nistConditions -join " OR ")))"
    }

    if ($ControlFamilies.Count -gt 0) {
        $familyConditions = $ControlFamilies | ForEach-Object {
            "v.Control_Families LIKE '%$_%'"
        }
        $conditions += "($(($familyConditions -join " OR ")))"
    }

    if ($CCIReferences.Count -gt 0) {
        $cciConditions = $CCIReferences | ForEach-Object {
            "v.CCI_References LIKE '%$_%'"
        }
        $conditions += "($(($cciConditions -join " OR ")))"
    }

    if ($conditions.Count -gt 0) {
        $query += " WHERE " + ($conditions -join " AND ")
    }

    $query += " ORDER BY sf.File_Name, v.Group_ID"

    if ($Limit -and $Limit -gt 0) {
        $query += " LIMIT $Limit"
    }

    $results = $Connection.ExecuteQuery($query)

    if ($ExportToCsv -and $OutputPath) {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        Write-Host "Search results exported to $OutputPath" -ForegroundColor Green
    }

    return $results
}

function Get-ComplianceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$false)]
        [string]$StigFile,

        [Parameter(Mandatory=$false)]
        [string]$ControlFamily,

        [Parameter(Mandatory=$false)]
        [switch]$IncludeTrends = $false,

        [Parameter(Mandatory=$false)]
        [switch]$ExportToExcel,

        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $report = @{
        Summary = @{}
        ByFamily = @()
        BySeverity = @{}
        ByStatus = @{}
        Trends = @()
        Recommendations = @()
    }

    # Get overall summary
    $summaryQuery = @"
    SELECT
        COUNT(*) as Total_Vulnerabilities,
        SUM(IIF(Status = 'Open', 1, 0)) as Open_Count,
        SUM(IIF(Status = 'NotAFinding' OR Status = 'Not_A_Finding', 1, 0)) as Compliant_Count,
        SUM(IIF(Status = 'Not_Reviewed', 1, 0)) as NotReviewed_Count,
        SUM(IIF(Severity = 'high' OR Severity = 'critical', 1, 0)) as High_Count,
        SUM(IIF(Severity = 'medium', 1, 0)) as Medium_Count,
        SUM(IIF(Severity = 'low', 1, 0)) as Low_Count
    FROM Vulnerabilities v
"@

    if ($StigFile) {
        $summaryQuery += " INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID WHERE sf.File_Name LIKE '%$StigFile%'"
    }

    $summary = $Connection.ExecuteQuery($summaryQuery)

    if ($summary.Rows.Count -gt 0) {
        $row = $summary.Rows[0]
        $total = $row.Total_Vulnerabilities
        $compliant = $row.Compliant_Count
        $report.Summary = @{
            TotalVulnerabilities = $total
            OpenCount = $row.Open_Count
            CompliantCount = $compliant
            NotReviewedCount = $row.NotReviewed_Count
            HighCount = $row.High_Count
            MediumCount = $row.Medium_Count
            LowCount = $row.Low_Count
            ComplianceRate = if ($total -gt 0) { [math]::Round(($compliant / $total) * 100, 2) } else { 0 }
        }
    }

    # Get family breakdown
    $familyQuery = @"
    SELECT
        nf.Family_Code,
        nf.Family_Name,
        COUNT(DISTINCT v.Vulnerability_ID) as Vulnerability_Count,
        SUM(IIF(v.Status = 'Open', 1, 0)) as Open_Count,
        SUM(IIF(v.Status = 'NotAFinding' OR v.Status = 'Not_A_Finding', 1, 0)) as Compliant_Count,
        SUM(IIF(v.Status = 'Not_Reviewed', 1, 0)) as NotReviewed_Count
    FROM NIST_Families nf
    LEFT JOIN Vulnerabilities v ON nf.Family_Code = ANY (SELECT * FROM SplitString(v.Control_Families, ','))
"@

    if ($StigFile) {
        $familyQuery += " INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID AND sf.File_Name LIKE '%$StigFile%'"
    }

    $familyQuery += " GROUP BY nf.Family_Code, nf.Family_Name ORDER BY nf.Family_Code"

    $familyResults = $Connection.ExecuteQuery($familyQuery)

    foreach ($row in $familyResults.Rows) {
        $familyReport = @{
            FamilyCode = $row.Family_Code
            FamilyName = $row.Family_Name
            TotalCount = $row.Vulnerability_Count
            OpenCount = $row.Open_Count
            CompliantCount = $row.Compliant_Count
            NotReviewedCount = $row.NotReviewed_Count
            ComplianceRate = if ($row.Vulnerability_Count -gt 0) { [math]::Round(($row.Compliant_Count / $row.Vulnerability_Count) * 100, 2) } else { 0 }
        }
        $report.ByFamily += $familyReport
    }

    # Get severity and status breakdowns
    $breakdownQuery = @"
    SELECT Severity, Status, COUNT(*) as Count
    FROM Vulnerabilities v
"@

    if ($StigFile) {
        $breakdownQuery += " INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID WHERE sf.File_Name LIKE '%$StigFile%'"
    }

    $breakdownQuery += " GROUP BY Severity, Status"

    $breakdownResults = $Connection.ExecuteQuery($breakdownQuery)

    foreach ($row in $breakdownResults.Rows) {
        if (-not $report.BySeverity.ContainsKey($row.Severity)) {
            $report.BySeverity[$row.Severity] = @{}
        }
        $report.BySeverity[$row.Severity][$row.Status] = $row.Count

        if (-not $report.ByStatus.ContainsKey($row.Status)) {
            $report.ByStatus[$row.Status] = @{}
        }
        $report.ByStatus[$row.Status][$row.Severity] = $row.Count
    }

    # Generate recommendations
    $report.Recommendations = Get-ComplianceRecommendations -Connection $Connection -StigFile $StigFile

    if ($ExportToExcel -and $OutputPath) {
        Export-ComplianceReportToExcel -Report $report -OutputPath $OutputPath -Connection $Connection
        Write-Host "Compliance report exported to $OutputPath" -ForegroundColor Green
    }

    return $report
}

function Get-ComplianceRecommendations {
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$false)]
        [string]$StigFile
    )

    $recommendations = @()

    # Get families with low compliance rates
    $lowComplianceQuery = @"
    SELECT
        nf.Family_Code,
        nf.Family_Name,
        COUNT(DISTINCT v.Vulnerability_ID) as Total_Count,
        SUM(IIF(v.Status = 'NotAFinding' OR v.Status = 'Not_A_Finding', 1, 0)) as Compliant_Count,
        ROUND(
            SUM(IIF(v.Status = 'NotAFinding' OR v.Status = 'Not_A_Finding', 1, 0)) /
            NULLIF(COUNT(DISTINCT v.Vulnerability_ID), 0) * 100,
            2
        ) as Compliance_Rate
    FROM NIST_Families nf
    LEFT JOIN Vulnerabilities v ON nf.Family_Code = ANY (SELECT * FROM SplitString(v.Control_Families, ','))
"@

    if ($StigFile) {
        $lowComplianceQuery += " INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID AND sf.File_Name LIKE '%$StigFile%'"
    }

    $lowComplianceQuery += @"
    GROUP BY nf.Family_Code, nf.Family_Name
    HAVING Compliance_Rate < 80 AND Total_Count > 0
    ORDER BY Compliance_Rate
"@

    $lowComplianceResults = $Connection.ExecuteQuery($lowComplianceQuery)

    foreach ($row in $lowComplianceResults.Rows) {
        $recommendations += @{
            Type = "LowCompliance"
            Family = $row.Family_Code
            Message = "Control family $($row.Family_Code) has only $($row.Compliance_Rate)% compliance rate. Focus remediation efforts here."
            Priority = if ($row.Compliance_Rate -lt 50) { "High" } else { "Medium" }
        }
    }

    # Get high severity open items
    $highSeverityQuery = @"
    SELECT v.Group_ID, v.Rule_Title, v.Severity, sf.STIG_Title
    FROM Vulnerabilities v
    INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID
    WHERE (v.Severity = 'high' OR v.Severity = 'critical') AND v.Status = 'Open'
"@

    if ($StigFile) {
        $highSeverityQuery += " AND sf.File_Name LIKE '%$StigFile%'"
    }

    $highSeverityQuery += " ORDER BY v.Severity DESC, v.Group_ID"

    $highSeverityResults = $Connection.ExecuteQuery($highSeverityQuery)

    if ($highSeverityResults.Rows.Count -gt 0) {
        $recommendations += @{
            Type = "HighSeverity"
            Message = "$($highSeverityResults.Rows.Count) high/critical severity vulnerabilities are still open. These should be prioritized."
            Priority = "Critical"
            Count = $highSeverityResults.Rows.Count
        }
    }

    # Get not reviewed items
    $notReviewedQuery = @"
    SELECT COUNT(*) as NotReviewed_Count
    FROM Vulnerabilities v
"@

    if ($StigFile) {
        $notReviewedQuery += " INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID AND sf.File_Name LIKE '%$StigFile%'"
    }

    $notReviewedQuery += " WHERE v.Status = 'Not_Reviewed'"

    $notReviewedResults = $Connection.ExecuteQuery($notReviewedQuery)

    if ($notReviewedResults.Rows.Count -gt 0 -and $notReviewedResults.Rows[0].NotReviewed_Count -gt 0) {
        $notReviewedCount = $notReviewedResults.Rows[0].NotReviewed_Count
        $recommendations += @{
            Type = "NotReviewed"
            Message = "$notReviewedCount items are still not reviewed. Complete the review process to improve compliance visibility."
            Priority = "Medium"
            Count = $notReviewedCount
        }
    }

    return $recommendations
}

# ========================================
# TREND ANALYSIS
# ========================================

function Get-TrendAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$false)]
        [int]$DaysBack = 30,

        [Parameter(Mandatory=$false)]
        [string]$StigFile
    )

    if (-not $Connection.IsConnected) {
        throw "Database connection is not open"
    }

    $trendData = @{
        DailyTrends = @()
        WeeklyTrends = @()
        MonthlyTrends = @()
        Summary = @{}
    }

    # Daily trends for the last N days
    $dailyQuery = @"
    SELECT
        DATE(v.Created_Date) as Date,
        COUNT(*) as New_Vulnerabilities,
        SUM(IIF(v.Status = 'Open', 1, 0)) as Open_Count,
        SUM(IIF(v.Status = 'NotAFinding' OR v.Status = 'Not_A_Finding', 1, 0)) as Compliant_Count
    FROM Vulnerabilities v
"@

    if ($StigFile) {
        $dailyQuery += " INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID AND sf.File_Name LIKE '%$StigFile%'"
    }

    $dailyQuery += @"
    WHERE v.Created_Date >= DATE('now', '-$DaysBack days')
    GROUP BY DATE(v.Created_Date)
    ORDER BY Date
"@

    $dailyResults = $Connection.ExecuteQuery($dailyQuery)

    foreach ($row in $dailyResults.Rows) {
        $trendData.DailyTrends += @{
            Date = $row.Date
            NewVulnerabilities = $row.New_Vulnerabilities
            OpenCount = $row.Open_Count
            CompliantCount = $row.Compliant_Count
        }
    }

    # Calculate summary trends
    if ($trendData.DailyTrends.Count -gt 1) {
        $firstDay = $trendData.DailyTrends[0]
        $lastDay = $trendData.DailyTrends[-1]

        $trendData.Summary = @{
            TotalNewVulnerabilities = ($trendData.DailyTrends | Measure-Object -Property NewVulnerabilities -Sum).Sum
            AverageDailyNew = [math]::Round(($trendData.DailyTrends | Measure-Object -Property NewVulnerabilities -Average).Average, 2)
            ComplianceTrend = $lastDay.CompliantCount - $firstDay.CompliantCount
            OpenTrend = $lastDay.OpenCount - $firstDay.OpenCount
        }
    }

    return $trendData
}

# ========================================
# CUSTOM REPORT GENERATION
# ========================================

function New-CustomReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection,

        [Parameter(Mandatory=$true)]
        [string]$ReportName,

        [Parameter(Mandatory=$true)]
        [hashtable]$Criteria,

        [Parameter(Mandatory=$false)]
        [string[]]$Columns = @(),

        [Parameter(Mandatory=$false)]
        [switch]$IncludeCharts = $true,

        [Parameter(Mandatory=$false)]
        [switch]$ExportToExcel,

        [Parameter(Mandatory=$false)]
        [string]$OutputPath
    )

    $report = @{
        Name = $ReportName
        GeneratedDate = Get-Date
        Criteria = $Criteria
        Data = @()
        Summary = @{}
    }

    # Build query based on criteria
    $query = "SELECT "
    if ($Columns.Count -gt 0) {
        $query += ($Columns -join ", ")
    } else {
        $query += "v.*, sf.File_Name, sf.STIG_Title"
    }

    $query += " FROM Vulnerabilities v INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID"

    # Apply criteria
    $conditions = @()
    foreach ($key in $Criteria.Keys) {
        $value = $Criteria[$key]
        switch ($key) {
            "StigFile" { $conditions += "sf.File_Name LIKE '%$value%'" }
            "Severity" { $conditions += "v.Severity = '$value'" }
            "Status" { $conditions += "v.Status = '$value'" }
            "NISTControl" { $conditions += "v.NIST_Controls LIKE '%$value%'" }
            "ControlFamily" { $conditions += "v.Control_Families LIKE '%$value%'" }
            "DateFrom" { $conditions += "v.Created_Date >= '$value'" }
            "DateTo" { $conditions += "v.Created_Date <= '$value'" }
        }
    }

    if ($conditions.Count -gt 0) {
        $query += " WHERE " + ($conditions -join " AND ")
    }

    $query += " ORDER BY sf.File_Name, v.Group_ID"

    # Execute query
    $results = $Connection.ExecuteQuery($query)
    $report.Data = $results.Rows

    # Generate summary
    $report.Summary = @{
        TotalRecords = $results.Rows.Count
        UniqueStigFiles = ($results.Rows | Select-Object -ExpandProperty STIG_Title -Unique).Count
        SeverityBreakdown = @{}
        StatusBreakdown = @{}
    }

    # Calculate breakdowns
    foreach ($row in $results.Rows) {
        $severity = $row.Severity
        $status = $row.Status

        if ($report.Summary.SeverityBreakdown.ContainsKey($severity)) {
            $report.Summary.SeverityBreakdown[$severity]++
        } else {
            $report.Summary.SeverityBreakdown[$severity] = 1
        }

        if ($report.Summary.StatusBreakdown.ContainsKey($status)) {
            $report.Summary.StatusBreakdown[$status]++
        } else {
            $report.Summary.StatusBreakdown[$status] = 1
        }
    }

    if ($ExportToExcel -and $OutputPath) {
        Export-CustomReportToExcel -Report $report -OutputPath $OutputPath
        Write-Host "Custom report exported to $OutputPath" -ForegroundColor Green
    }

    return $report
}

# ========================================
# EXCEL EXPORT FOR REPORTS
# ========================================

function Export-ComplianceReportToExcel {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Report,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection
    )

    $excel = $null
    $workbook = $null

    try {
        # Create Excel application
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $excel.DisplayAlerts = $false
        $workbook = $excel.Workbooks.Add()

        # Set performance optimizations
        $excel.ScreenUpdating = $false

        # Create Summary Sheet
        $summarySheet = $workbook.Worksheets.Item(1)
        $summarySheet.Name = "Compliance Summary"

        # Title
        $summarySheet.Cells.Item(1, 1) = "STIG Compliance Report"
        $summarySheet.Cells.Item(1, 1).Font.Size = 18
        $summarySheet.Cells.Item(1, 1).Font.Bold = $true
        $titleRange = $summarySheet.Range("A1:D1")
        $titleRange.Merge() | Out-Null
        $titleRange.HorizontalAlignment = -4108

        # Report metadata
        $row = 3
        $summarySheet.Cells.Item($row, 1) = "Report Generated:"
        $summarySheet.Cells.Item($row, 2) = $Report.Summary.TotalVulnerabilities
        $row++

        $summarySheet.Cells.Item($row, 1) = "Compliance Rate:"
        $summarySheet.Cells.Item($row, 2) = "$($Report.Summary.ComplianceRate)%"
        $row += 2

        # Summary statistics
        $summarySheet.Cells.Item($row, 1) = "Category"
        $summarySheet.Cells.Item($row, 2) = "Count"
        $summarySheet.Cells.Item($row, 3) = "Percentage"
        $summarySheet.Cells.Item($row, 1).Font.Bold = $true
        $summarySheet.Cells.Item($row, 2).Font.Bold = $true
        $summarySheet.Cells.Item($row, 3).Font.Bold = $true

        $row++
        $total = $Report.Summary.TotalVulnerabilities

        $categories = @(
            @("Open", $Report.Summary.OpenCount),
            @("Compliant", $Report.Summary.CompliantCount),
            @("Not Reviewed", $Report.Summary.NotReviewedCount),
            @("High Severity", $Report.Summary.HighCount),
            @("Medium Severity", $Report.Summary.MediumCount),
            @("Low Severity", $Report.Summary.LowCount)
        )

        foreach ($category in $categories) {
            $percentage = if ($total -gt 0) { [math]::Round(($category[1] / $total) * 100, 2) } else { 0 }
            $summarySheet.Cells.Item($row, 1) = $category[0]
            $summarySheet.Cells.Item($row, 2) = $category[1]
            $summarySheet.Cells.Item($row, 3) = "$percentage%"
            $row++
        }

        # Create Family Breakdown Sheet
        $familySheet = $workbook.Worksheets.Add()
        $familySheet.Name = "Control Families"

        # Headers
        $row = 1
        $headers = @("Family Code", "Family Name", "Total", "Open", "Compliant", "Not Reviewed", "Compliance %")
        for ($col = 1; $col -le $headers.Count; $col++) {
            $familySheet.Cells.Item($row, $col) = $headers[$col - 1]
            $familySheet.Cells.Item($row, $col).Font.Bold = $true
            $familySheet.Cells.Item($row, $col).Interior.Color = 0xD9E1F2
        }

        # Data
        $row = 2
        foreach ($family in $Report.ByFamily) {
            $familySheet.Cells.Item($row, 1) = $family.FamilyCode
            $familySheet.Cells.Item($row, 2) = $family.FamilyName
            $familySheet.Cells.Item($row, 3) = $family.TotalCount
            $familySheet.Cells.Item($row, 4) = $family.OpenCount
            $familySheet.Cells.Item($row, 5) = $family.CompliantCount
            $familySheet.Cells.Item($row, 6) = $family.NotReviewedCount
            $familySheet.Cells.Item($row, 7).Formula = "=IF(C$row>0,E$row/C$row,0)"
            $familySheet.Cells.Item($row, 7).NumberFormat = "0.0%"
            $row++
        }

        # Auto-fit columns
        $summarySheet.Columns.Item(1).ColumnWidth = 20
        $summarySheet.Columns.Item(2).ColumnWidth = 15
        $summarySheet.Columns.Item(3).ColumnWidth = 15

        $familySheet.Columns.Item(1).ColumnWidth = 12
        $familySheet.Columns.Item(2).ColumnWidth = 25
        $familySheet.Columns.Item(3).ColumnWidth = 10
        $familySheet.Columns.Item(4).ColumnWidth = 10
        $familySheet.Columns.Item(5).ColumnWidth = 12
        $familySheet.Columns.Item(6).ColumnWidth = 15
        $familySheet.Columns.Item(7).ColumnWidth = 15

        # Save workbook
        $excel.ScreenUpdating = $true
        $workbook.SaveAs($OutputPath, 51)

        $workbook.Close($false)
    }
    catch {
        throw "Failed to export compliance report: $($_.Exception.Message)"
    }
    finally {
        # Cleanup
        if ($workbook) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($workbook) } catch {}
        }
        if ($excel) {
            try { $excel.Quit() } catch {}
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) } catch {}
        }
    }
}

function Export-CustomReportToExcel {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Report,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )

    $excel = $null
    $workbook = $null

    try {
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $excel.DisplayAlerts = $false
        $workbook = $excel.Workbooks.Add()

        $sheet = $workbook.Worksheets.Item(1)
        $sheet.Name = "Custom Report"

        # Title
        $sheet.Cells.Item(1, 1) = $Report.Name
        $sheet.Cells.Item(1, 1).Font.Size = 16
        $sheet.Cells.Item(1, 1).Font.Bold = $true
        $titleRange = $sheet.Range("A1:D1")
        $titleRange.Merge() | Out-Null

        # Metadata
        $row = 3
        $sheet.Cells.Item($row, 1) = "Generated:"
        $sheet.Cells.Item($row, 2) = $Report.GeneratedDate.ToString()
        $row += 2

        # Criteria
        $sheet.Cells.Item($row, 1) = "Criteria Applied:"
        $sheet.Cells.Item($row, 1).Font.Bold = $true
        $row++

        foreach ($key in $Report.Criteria.Keys) {
            $sheet.Cells.Item($row, 1) = "$key`: $($Report.Criteria[$key])"
            $row++
        }
        $row += 2

        # Summary
        $sheet.Cells.Item($row, 1) = "Summary"
        $sheet.Cells.Item($row, 1).Font.Bold = $true
        $sheet.Cells.Item($row, 1).Font.Size = 14
        $row += 2

        $sheet.Cells.Item($row, 1) = "Total Records:"
        $sheet.Cells.Item($row, 2) = $Report.Summary.TotalRecords
        $row++

        $sheet.Cells.Item($row, 1) = "Unique STIG Files:"
        $sheet.Cells.Item($row, 2) = $Report.Summary.UniqueStigFiles
        $row += 2

        # Breakdown tables
        if ($Report.Summary.SeverityBreakdown.Count -gt 0) {
            $sheet.Cells.Item($row, 1) = "Severity Breakdown"
            $sheet.Cells.Item($row, 1).Font.Bold = $true
            $row++

            $sheet.Cells.Item($row, 1) = "Severity"
            $sheet.Cells.Item($row, 2) = "Count"
            $sheet.Cells.Item($row, 1).Font.Bold = $true
            $sheet.Cells.Item($row, 2).Font.Bold = $true
            $row++

            foreach ($severity in $Report.Summary.SeverityBreakdown.Keys) {
                $sheet.Cells.Item($row, 1) = $severity
                $sheet.Cells.Item($row, 2) = $Report.Summary.SeverityBreakdown[$severity]
                $row++
            }
            $row += 2
        }

        # Data table
        if ($Report.Data.Count -gt 0) {
            $sheet.Cells.Item($row, 1) = "Detailed Results"
            $sheet.Cells.Item($row, 1).Font.Bold = $true
            $sheet.Cells.Item($row, 1).Font.Size = 14
            $row += 2

            # Headers
            $col = 1
            $Report.Data[0].PSObject.Properties | ForEach-Object {
                $sheet.Cells.Item($row, $col) = $_.Name
                $sheet.Cells.Item($row, $col).Font.Bold = $true
                $sheet.Cells.Item($row, $col).Interior.Color = 0xD9E1F2
                $col++
            }
            $row++

            # Data
            foreach ($item in $Report.Data) {
                $col = 1
                $item.PSObject.Properties | ForEach-Object {
                    $sheet.Cells.Item($row, $col) = $_.Value
                    $col++
                }
                $row++
            }
        }

        # Auto-fit columns
        $usedRange = $sheet.UsedRange
        $usedRange.EntireColumn.AutoFit() | Out-Null

        # Save
        $excel.ScreenUpdating = $true
        $workbook.SaveAs($OutputPath, 51)
        $workbook.Close($false)
    }
    catch {
        throw "Failed to export custom report: $($_.Exception.Message)"
    }
    finally {
        # Cleanup
        if ($workbook) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($workbook) } catch {}
        }
        if ($excel) {
            try { $excel.Quit() } catch {}
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($excel) } catch {}
        }
    }
}

# ========================================
# PERFORMANCE MONITORING
# ========================================

function Get-PerformanceMetrics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [DatabaseConnection]$Connection
    )

    $metrics = @{
        DatabaseSize = 0
        TableCounts = @{}
        IndexUsage = @{}
        QueryPerformance = @{}
    }

    # Get database size
    try {
        $dbPath = $Connection.ConnectionString -replace '.*Data Source=(.*?);.*', '$1'
        if (Test-Path $dbPath) {
            $metrics.DatabaseSize = (Get-Item $dbPath).Length
        }
    }
    catch {
        Write-Warning "Could not get database size: $($_.Exception.Message)"
    }

    # Get table counts
    $tables = @("CCI_Mappings", "STIG_Files", "Vulnerabilities", "Vulnerability_Details", "Analysis_Results", "Export_History", "NIST_Families")

    foreach ($table in $tables) {
        try {
            $countQuery = "SELECT COUNT(*) as Count FROM $table"
            $result = $Connection.ExecuteQuery($countQuery)
            $metrics.TableCounts[$table] = $result.Rows[0].Count
        }
        catch {
            Write-Warning "Could not get count for $table`: $($_.Exception.Message)"
        }
    }

    return $metrics
}

# Export module functions
Export-ModuleMember -Function @(
    'Search-Vulnerabilities',
    'Get-ComplianceReport',
    'Get-ComplianceRecommendations',
    'Get-TrendAnalysis',
    'New-CustomReport',
    'Export-ComplianceReportToExcel',
    'Export-CustomReportToExcel',
    'Get-PerformanceMetrics'
)
