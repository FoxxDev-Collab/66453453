# STIG Analysis Tool v2.0 - Database Edition

## Overview

The STIG Analysis Tool v2.0 Database Edition is a comprehensive, enterprise-grade solution for STIG (Security Technical Implementation Guide) analysis with persistent database storage and modern web-based user interface. This enhanced version provides professional-grade features for large-scale STIG compliance management.

## 🚀 Key Features

### ✅ Database Integration
- **MS Access 2016 Backend**: Persistent storage with full relational database capabilities
- **Optimized Performance**: Indexed queries for fast data retrieval
- **Data Integrity**: Foreign key relationships and constraints
- **Scalable Architecture**: Handles thousands of STIG files and millions of vulnerabilities

### ✅ Modern Web Interface
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Professional UI**: Modern HTML/CSS/JS with intuitive navigation
- **Real-time Dashboard**: Live compliance metrics and visualizations
- **Interactive Charts**: Visual representation of compliance data

### ✅ Advanced Analytics
- **Comprehensive Reporting**: Multiple report types with customizable criteria
- **Trend Analysis**: Historical compliance tracking and forecasting
- **Smart Recommendations**: AI-powered remediation suggestions
- **Performance Monitoring**: Database health and optimization metrics

### ✅ Enhanced Export Capabilities
- **Professional Excel Reports**: Multi-sheet workbooks with charts and formatting
- **Custom Report Builder**: Create reports based on specific criteria
- **Automated Scheduling**: Generate reports on demand or scheduled basis
- **Export History Tracking**: Audit trail of all exports

## 📋 System Requirements

- **Windows 10 or Windows 11**
- **PowerShell 5.1 or higher**
- **Microsoft Access Database Engine 2016** (free download from Microsoft)
- **Microsoft Office 2016 or higher** (for Excel export features)
- **Internet Explorer 11+ or modern browser** (for web interface)

## 🛠️ Installation

1. **Install Microsoft Access Database Engine 2016**:
   ```powershell
   # Download from: https://www.microsoft.com/en-us/download/details.aspx?id=54920
   # Install the 64-bit version for 64-bit PowerShell
   ```

2. **Extract all files** to a dedicated directory

3. **Initialize the database**:
   ```powershell
   .\STIGAnalysis-Database.ps1
   ```
   This will automatically create the database and schema

## 🎯 Quick Start

1. **Start the application**:
   ```powershell
   .\STIGAnalysis-Database.ps1
   ```

2. **Open your browser** and navigate to `http://localhost:8080`

3. **Import CCI mappings**:
   - Go to "Import Data" tab
   - Click "Browse" to select your `U_CCI_List.xml` file
   - Click "Import CCI Mappings"

4. **Import STIG files**:
   - Click "Add STIG Files" or drag-and-drop CKL/CKLB files
   - Files are automatically parsed and stored in the database

5. **View results**:
   - Dashboard shows real-time compliance metrics
   - Browse tab allows filtering and detailed examination
   - Reports tab provides advanced analytics

## 📊 Database Schema

The system uses a comprehensive relational database with the following main tables:

### Core Tables
- **CCI_Mappings**: Maps CCI IDs to NIST 800-53 controls
- **STIG_Files**: Metadata for imported STIG files
- **Vulnerabilities**: Detailed vulnerability data with relationships
- **NIST_Families**: Reference data for control families

### Analytics Tables
- **Analysis_Results**: Pre-calculated compliance metrics
- **Export_History**: Audit trail for all exports
- **Vulnerability_Details**: Additional metadata storage

## 🔧 Module Architecture

### STIGDatabase.psm1
- **Database Connection Management**: Connection pooling and optimization
- **CRUD Operations**: Complete data access layer
- **Query Optimization**: Efficient SQL generation and execution

### STIGExport.psm1
- **Excel Integration**: Professional report generation
- **Chart Creation**: Visual data representation
- **Template Management**: Consistent formatting across reports

### STIGReporting.psm1
- **Advanced Search**: Multi-criteria filtering and search
- **Custom Reports**: User-defined report generation
- **Trend Analysis**: Historical data analysis and forecasting

## 🌐 Web Interface

### Dashboard Tab
- Real-time compliance metrics
- Visual charts and graphs
- Recent activity summary
- Quick action buttons

### Import Tab
- Drag-and-drop file upload
- Progress tracking
- Batch processing capabilities
- Error handling and validation

### Browse Tab
- Advanced filtering options
- Sortable data tables
- Detailed vulnerability views
- Export filtered results

### Reports Tab
- Pre-built compliance reports
- Custom report builder
- Trend analysis charts
- Automated report generation

### Export Tab
- Excel export with multiple sheets
- PDF report generation (planned)
- Export history and management
- Scheduled export capabilities

## 📈 Advanced Features

### Search and Filtering
- **Multi-field Search**: Search across titles, descriptions, and content
- **Advanced Filters**: Filter by severity, status, control family, etc.
- **Saved Searches**: Bookmark frequently used search criteria
- **Export Filtered Results**: Export only filtered data

### Compliance Analysis
- **NIST 800-53 Mapping**: Complete control family coverage
- **Risk Assessment**: Automated risk scoring and prioritization
- **Gap Analysis**: Identify compliance gaps and remediation priorities
- **Trend Tracking**: Monitor compliance improvements over time

### Reporting Capabilities
- **Executive Dashboards**: High-level compliance summaries
- **Technical Reports**: Detailed vulnerability analysis
- **Compliance Scorecards**: Standardized reporting formats
- **Custom Analytics**: User-defined metrics and KPIs

## 🔒 Security Considerations

- **Air-gapped Compatible**: No external dependencies or internet access required
- **Local Processing**: All data processing occurs on local machine
- **Encrypted Storage**: Database-level encryption options available
- **Access Controls**: File system permissions protect sensitive data

## 🚀 Performance Optimizations

- **Database Indexing**: Optimized queries for fast data retrieval
- **Connection Pooling**: Efficient database connection management
- **Memory Management**: Proper COM object cleanup and garbage collection
- **Batch Processing**: Efficient handling of large STIG files

## 🛠️ Customization

### Adding Custom Fields
```sql
ALTER TABLE Vulnerabilities ADD COLUMN CustomField TEXT;
```

### Creating Custom Reports
```powershell
$criteria = @{
    Severity = "high"
    Status = "Open"
    ControlFamily = "AC"
}

$report = New-CustomReport -Connection $db -ReportName "High Priority Items" -Criteria $criteria
```

### Extending Database Schema
```powershell
# Add new table for custom tracking
$query = @"
CREATE TABLE Custom_Tracking (
    ID AUTOINCREMENT PRIMARY KEY,
    Vulnerability_ID INTEGER,
    Tracking_Date DATETIME,
    Status VARCHAR(50),
    Notes TEXT,
    FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID)
);
"@

$db.ExecuteNonQuery($query)
```

## 📚 API Reference

### Database Operations
```powershell
# Connect to database
$db = [DatabaseConnection]::new("STIGAnalysis.accdb")
$db.Connect()

# Query vulnerabilities
$vulnerabilities = Get-Vulnerabilities -Connection $db -Severity "high"

# Import STIG file
Import-STIGFileToDatabase -Path "stig.ckl" -Connection $db
```

### Reporting Functions
```powershell
# Generate compliance report
$report = Get-ComplianceReport -Connection $db -StigFile "Windows 10"

# Search vulnerabilities
$results = Search-Vulnerabilities -Connection $db -SearchTerm "password" -Severities @("high", "medium")

# Create custom report
$custom = New-CustomReport -Connection $db -ReportName "Custom Analysis" -Criteria @{Status = "Open"}
```

## 🔧 Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Ensure Microsoft Access Database Engine 2016 is installed
   - Check file permissions on database directory
   - Verify PowerShell execution policy

2. **Excel Export Issues**
   - Ensure Microsoft Office 2016+ is installed
   - Check for running Excel processes
   - Verify sufficient disk space

3. **Web Interface Not Loading**
   - Check if port 8080 is available
   - Ensure no firewall blocking
   - Verify PowerShell script is running

### Performance Tuning

1. **Database Optimization**
   ```sql
   -- Rebuild indexes periodically
   REINDEX CCI_Mappings;
   REINDEX Vulnerabilities;
   ```

2. **Memory Management**
   ```powershell
   # Force garbage collection
   [System.GC]::Collect()
   [System.GC]::WaitForPendingFinalizers()
   ```

## 🎯 Best Practices

1. **Regular Backups**: Backup database regularly
2. **Batch Imports**: Import large numbers of files in batches
3. **Index Maintenance**: Periodically rebuild database indexes
4. **Report Archiving**: Archive old reports to maintain performance
5. **User Training**: Train users on proper data classification

## 📞 Support

For technical support or feature requests:
- Review the troubleshooting section above
- Check system requirements and prerequisites
- Ensure all dependencies are properly installed
- Verify file permissions and access rights

## 🔄 Version History

### v2.0 (Database Edition)
- Complete database backend with MS Access 2016
- Modern web-based user interface
- Advanced search and filtering capabilities
- Enhanced Excel export with charts and formatting
- Comprehensive reporting and analytics
- Performance optimizations and scalability improvements

### v1.0 (Original Edition)
- Basic Windows Forms GUI
- In-memory data processing
- Simple Excel export
- Basic STIG parsing functionality

## 📄 License

This software is provided as-is for educational and operational use in authorized environments. Ensure compliance with applicable security policies and regulations when using this tool in production environments.

---

**STIG Analysis Tool v2.0 Database Edition** - Professional STIG compliance management with persistent storage and advanced analytics.
