-- STIG Analysis Database Schema for MS Access 2016
-- This schema supports persistent storage for STIG analysis with PowerShell GUI

-- ========================================
-- TABLES FOR CCI MAPPINGS
-- ========================================

-- CCI to NIST Control Mappings
CREATE TABLE CCI_Mappings (
    CCI_ID VARCHAR(20) PRIMARY KEY,
    NIST_Controls TEXT,
    Control_Families TEXT,
    Description TEXT,
    Created_Date DATETIME DEFAULT NOW(),
    Modified_Date DATETIME DEFAULT NOW()
);

-- NIST Control Families Reference
CREATE TABLE NIST_Families (
    Family_Code VARCHAR(5) PRIMARY KEY,
    Family_Name VARCHAR(100),
    Description TEXT,
    Control_Count INTEGER,
    Subcontrol_Count INTEGER,
    Total_Count INTEGER,
    Applicable_Count INTEGER,
    Not_Applicable_Count INTEGER,
    Created_Date DATETIME DEFAULT NOW()
);

-- ========================================
-- TABLES FOR STIG FILES
-- ========================================

-- STIG Files Information
CREATE TABLE STIG_Files (
    File_ID AUTOINCREMENT PRIMARY KEY,
    File_Name VARCHAR(255),
    File_Path TEXT,
    File_Type VARCHAR(10), -- 'CKL', 'CKLB'
    STIG_Title VARCHAR(255),
    STIG_Version VARCHAR(50),
    Release_Date DATETIME,
    Import_Date DATETIME DEFAULT NOW(),
    File_Size BIGINT,
    Record_Count INTEGER,
    Processing_Status VARCHAR(20) DEFAULT 'Imported'
);

-- ========================================
-- TABLES FOR VULNERABILITIES
-- ========================================

-- Main Vulnerabilities Table
CREATE TABLE Vulnerabilities (
    Vulnerability_ID AUTOINCREMENT PRIMARY KEY,
    File_ID INTEGER,
    Group_ID VARCHAR(50),
    Rule_ID VARCHAR(50),
    Rule_Version VARCHAR(20),
    Rule_Title TEXT,
    Severity VARCHAR(20),
    Status VARCHAR(50),
    STIG_Name VARCHAR(255),

    -- CCI and NIST mappings (denormalized for performance)
    CCI_References TEXT, -- Comma-separated list of CCI IDs
    NIST_Controls TEXT,  -- Comma-separated list of NIST control IDs
    Control_Families TEXT, -- Comma-separated list of family codes

    -- Content fields
    Discussion TEXT,
    Check_Content TEXT,
    Fix_Text TEXT,
    Finding_Details TEXT,
    Comments TEXT,

    -- Metadata
    Created_Date DATETIME DEFAULT NOW(),
    Modified_Date DATETIME DEFAULT NOW(),

    FOREIGN KEY (File_ID) REFERENCES STIG_Files(File_ID)
);

-- Vulnerability Details (for additional metadata)
CREATE TABLE Vulnerability_Details (
    Detail_ID AUTOINCREMENT PRIMARY KEY,
    Vulnerability_ID INTEGER,
    Detail_Type VARCHAR(50), -- 'Reference', 'Check', 'Fix', etc.
    Detail_Key VARCHAR(100),
    Detail_Value TEXT,
    Created_Date DATETIME DEFAULT NOW(),

    FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID)
);

-- ========================================
-- TABLES FOR ANALYSIS AND REPORTING
-- ========================================

-- Analysis Results (for dashboard calculations)
CREATE TABLE Analysis_Results (
    Analysis_ID AUTOINCREMENT PRIMARY KEY,
    Analysis_Type VARCHAR(50), -- 'Compliance', 'Severity', 'Status'
    File_ID INTEGER,
    Control_Family VARCHAR(5),
    Total_Count INTEGER DEFAULT 0,
    Open_Count INTEGER DEFAULT 0,
    NotAFinding_Count INTEGER DEFAULT 0,
    NotReviewed_Count INTEGER DEFAULT 0,
    NotApplicable_Count INTEGER DEFAULT 0,
    High_Count INTEGER DEFAULT 0,
    Medium_Count INTEGER DEFAULT 0,
    Low_Count INTEGER DEFAULT 0,
    Compliance_Percentage DECIMAL(5,2) DEFAULT 0,
    Analysis_Date DATETIME DEFAULT NOW(),

    FOREIGN KEY (File_ID) REFERENCES STIG_Files(File_ID)
);

-- Export History
CREATE TABLE Export_History (
    Export_ID AUTOINCREMENT PRIMARY KEY,
    Export_Date DATETIME DEFAULT NOW(),
    Export_Type VARCHAR(20), -- 'Excel', 'PDF', 'CSV'
    File_Path TEXT,
    Record_Count INTEGER,
    Export_Status VARCHAR(20),
    Error_Message TEXT
);

-- ========================================
-- INDEXES FOR PERFORMANCE
-- ========================================

-- Indexes for CCI lookups
CREATE INDEX idx_CCI_Mappings_CCI_ID ON CCI_Mappings(CCI_ID);

-- Indexes for vulnerability queries
CREATE INDEX idx_Vulnerabilities_File_ID ON Vulnerabilities(File_ID);
CREATE INDEX idx_Vulnerabilities_Group_ID ON Vulnerabilities(Group_ID);
CREATE INDEX idx_Vulnerabilities_Rule_ID ON Vulnerabilities(Rule_ID);
CREATE INDEX idx_Vulnerabilities_Severity ON Vulnerabilities(Severity);
CREATE INDEX idx_Vulnerabilities_Status ON Vulnerabilities(Status);
CREATE INDEX idx_Vulnerabilities_NIST_Controls ON Vulnerabilities(NIST_Controls);
CREATE INDEX idx_Vulnerabilities_Control_Families ON Vulnerabilities(Control_Families);

-- Indexes for STIG files
CREATE INDEX idx_STIG_Files_File_Name ON STIG_Files(File_Name);
CREATE INDEX idx_STIG_Files_Import_Date ON STIG_Files(Import_Date);

-- ========================================
-- VIEWS FOR COMMON QUERIES
-- ========================================

-- View for Dashboard Summary
CREATE VIEW Dashboard_Summary AS
SELECT
    sf.File_Name,
    sf.STIG_Title,
    COUNT(v.Vulnerability_ID) as Total_Findings,
    SUM(IIF(v.Status = 'Open', 1, 0)) as Open_Count,
    SUM(IIF(v.Status = 'NotAFinding' OR v.Status = 'Not_A_Finding', 1, 0)) as NotAFinding_Count,
    SUM(IIF(v.Status = 'Not_Reviewed', 1, 0)) as NotReviewed_Count,
    SUM(IIF(v.Severity = 'high' OR v.Severity = 'critical', 1, 0)) as High_Count,
    SUM(IIF(v.Severity = 'medium', 1, 0)) as Medium_Count,
    SUM(IIF(v.Severity = 'low', 1, 0)) as Low_Count,
    ROUND(
        SUM(IIF(v.Status = 'NotAFinding' OR v.Status = 'Not_A_Finding', 1, 0)) /
        NULLIF(COUNT(v.Vulnerability_ID), 0) * 100,
        2
    ) as Compliance_Percentage
FROM STIG_Files sf
LEFT JOIN Vulnerabilities v ON sf.File_ID = v.File_ID
GROUP BY sf.File_ID, sf.File_Name, sf.STIG_Title;

-- View for NIST Control Family Summary
CREATE VIEW NIST_Family_Summary AS
SELECT
    nf.Family_Code,
    nf.Family_Name,
    COUNT(DISTINCT v.Vulnerability_ID) as Vulnerability_Count,
    SUM(IIF(v.Status = 'Open', 1, 0)) as Open_Count,
    SUM(IIF(v.Status = 'NotAFinding' OR v.Status = 'Not_A_Finding', 1, 0)) as Compliant_Count,
    ROUND(
        SUM(IIF(v.Status = 'NotAFinding' OR v.Status = 'Not_A_Finding', 1, 0)) /
        NULLIF(COUNT(DISTINCT v.Vulnerability_ID), 0) * 100,
        2
    ) as Compliance_Percentage
FROM NIST_Families nf
LEFT JOIN Vulnerabilities v ON nf.Family_Code = ANY (SELECT * FROM SplitString(v.Control_Families, ','))
GROUP BY nf.Family_Code, nf.Family_Name;

-- ========================================
-- STORED PROCEDURES (MS Access Queries)
-- ========================================

-- Query: Get Vulnerabilities by STIG File
-- SELECT v.*, sf.File_Name, sf.STIG_Title
-- FROM Vulnerabilities v
-- INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID
-- WHERE sf.File_ID = ?;

-- Query: Get Vulnerabilities by Severity
-- SELECT v.*, sf.File_Name
-- FROM Vulnerabilities v
-- INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID
-- WHERE v.Severity = ?
-- ORDER BY sf.File_Name, v.Group_ID;

-- Query: Get Vulnerabilities by NIST Control
-- SELECT v.*, sf.File_Name
-- FROM Vulnerabilities v
-- INNER JOIN STIG_Files sf ON v.File_ID = sf.File_ID
-- WHERE v.NIST_Controls LIKE '%' + ? + '%'
-- ORDER BY sf.File_Name, v.Group_ID;

-- Query: Update Analysis Results
-- UPDATE Analysis_Results SET
--     Total_Count = (SELECT COUNT(*) FROM Vulnerabilities WHERE File_ID = ?),
--     Open_Count = (SELECT COUNT(*) FROM Vulnerabilities WHERE File_ID = ? AND Status = 'Open'),
--     NotAFinding_Count = (SELECT COUNT(*) FROM Vulnerabilities WHERE File_ID = ? AND (Status = 'NotAFinding' OR Status = 'Not_A_Finding')),
--     High_Count = (SELECT COUNT(*) FROM Vulnerabilities WHERE File_ID = ? AND (Severity = 'high' OR Severity = 'critical')),
--     Medium_Count = (SELECT COUNT(*) FROM Vulnerabilities WHERE File_ID = ? AND Severity = 'medium'),
--     Low_Count = (SELECT COUNT(*) FROM Vulnerabilities WHERE File_ID = ? AND Severity = 'low'),
--     Compliance_Percentage = ROUND(
--         (SELECT COUNT(*) FROM Vulnerabilities WHERE File_ID = ? AND (Status = 'NotAFinding' OR Status = 'Not_A_Finding')) /
--         NULLIF((SELECT COUNT(*) FROM Vulnerabilities WHERE File_ID = ?), 0) * 100,
--         2
--     ),
--     Analysis_Date = NOW()
-- WHERE File_ID = ?;

-- ========================================
-- INITIAL DATA POPULATION
-- ========================================

-- Insert NIST Control Families (SP 800-53 Rev 5)
INSERT INTO NIST_Families (Family_Code, Family_Name, Description, Control_Count, Subcontrol_Count, Total_Count, Applicable_Count, Not_Applicable_Count) VALUES
('AC', 'Access Control', 'Controls for managing access to information systems', 23, 89, 112, 62, 50),
('AT', 'Awareness and Training', 'Controls for security awareness and training', 4, 6, 10, 7, 3),
('AU', 'Audit and Accountability', 'Controls for audit logging and accountability', 16, 41, 57, 40, 17),
('CA', 'Security Assessment and Authorization', 'Controls for security assessments', 8, 14, 22, 12, 10),
('CM', 'Configuration Management', 'Controls for system configuration', 11, 39, 50, 25, 25),
('CP', 'Contingency Planning', 'Controls for business continuity', 12, 36, 48, 7, 41),
('IA', 'Identification and Authentication', 'Controls for user identification', 11, 45, 56, 31, 25),
('IR', 'Incident Response', 'Controls for incident response', 10, 24, 34, 26, 8),
('MA', 'Maintenance', 'Controls for system maintenance', 6, 20, 26, 19, 7),
('MP', 'Media Protection', 'Controls for media protection', 8, 14, 22, 18, 4),
('PE', 'Physical and Environmental Protection', 'Controls for physical security', 19, 31, 50, 25, 25),
('PL', 'Planning', 'Controls for security planning', 6, 4, 10, 8, 2),
('PS', 'Personnel Security', 'Controls for personnel security', 8, 7, 15, 13, 2),
('RA', 'Risk Assessment', 'Controls for risk assessment', 5, 8, 13, 10, 3),
('SA', 'System and Services Acquisition', 'Controls for system acquisition', 19, 66, 85, 24, 61),
('SC', 'System and Communications Protection', 'Controls for system protection', 40, 75, 115, 53, 62),
('SI', 'System and Information Integrity', 'Controls for system integrity', 16, 66, 82, 38, 44),
('PM', 'Program Management', 'Controls for security program management', 16, 0, 16, 16, 0);

-- ========================================
-- UTILITY FUNCTIONS (VBA CODE)
-- ========================================

-- Function to split comma-separated strings for queries
-- Public Function SplitString(ByVal InputString As String, ByVal Delimiter As String) As String()
--     SplitString = Split(InputString, Delimiter)
-- End Function

-- Function to check if string contains a value
-- Public Function ContainsValue(ByVal Source As String, ByVal Search As String) As Boolean
--     ContainsValue = InStr(1, Source, Search, vbTextCompare) > 0
-- End Function
