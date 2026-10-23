# devsecops-demo

Repository: **nandhakumar-murugan / devsecops-demo**  
Author: **NANDHAKUMAR M (711724UCY129)**  
Course: **24UCY511 - Secure Software Systems**

## Overview
Automated DevSecOps pipeline and DAST dynamic baseline security scanning for web applications.

### Pipelines
1. **Security Pipeline (`security-pipeline.yml`)**:
   - Gitleaks (Secret Detection)
   - Bandit (SAST Python static code analysis)
   - Trivy (SCA Dependency Vulnerability Scanning)
2. **DAST Pipeline (`dast-pipeline.yml`)**:
   - OWASP ZAP Baseline Scan
   - Automated GitHub Issue creation for triage
