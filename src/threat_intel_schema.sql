-- Threat Intelligence Database Schema

-- Create schema
CREATE SCHEMA IF NOT EXISTS threat_intel;

-- CVE Table 
CREATE TABLE IF NOT EXISTS threat_intel.cves (
    cve_id VARCHAR(50) PRIMARY KEY,
    published_date TIMESTAMP,
    last_modified_date TIMESTAMP,
    cvss_score_3_1 FLOAT,
    cvss_vector_3_1 VARCHAR(200),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- CVE - CPE Mapping Table
CREATE TABLE IF NOT EXISTS threat_intel.cve_cpe_mapping (
    cve_id VARCHAR(50),
    cpe VARCHAR(300),
    PRIMARY KEY (cve_id, cpe),
    FOREIGN KEY (cve_id) REFERENCES threat_intel.cves(cve_id) 
);

-- EPSS Table 
CREATE TABLE IF NOT EXISTS threat_intel.epss (
    cve_id VARCHAR(50) PRIMARY KEY,
    epss_score FLOAT,
    epss_percentile FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- KEV Table 
CREATE TABLE IF NOT EXISTS threat_intel.kev (
    cve_id VARCHAR(50) PRIMARY KEY,
    product VARCHAR(200),
    date_added DATE,
    known_ransomware_use BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);