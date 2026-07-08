# Requirements Document

## Introduction

The Vulnerability Management Maturity Assessment (VMMA) application is a web-based tool that evaluates an organization's vulnerability management program maturity across 10 control domains based on the Rapid7 VMMA methodology. It replaces a CLI-based questionnaire with a browser interface, provides interactive assessment collection, calculates maturity scores on a 1–6 scale, and generates visual HTML reports with radar charts, gap analysis, and prioritized recommendations. The application supports pause/resume workflows, bulk answer operations, PDF export, and JSON-based assessment storage.

## Glossary

- **VMMA_App**: The Flask-based web application serving the assessment UI and API endpoints
- **Assessment_Engine**: The scoring and data-processing module that calculates domain maturity scores from questionnaire responses
- **Report_Generator**: The module that produces HTML reports with radar charts, gap analysis, and recommendations from assessment JSON data
- **Domain**: One of 10 vulnerability management control areas (Governance, Risk Management, Asset Management, Admin Privileges, Discovery and Scanning, Vulnerability Analysis, Remediation, Change Management, Reporting, Security Program)
- **Maturity_Level**: A score from 1 (Preliminary) to 6 (Innovating) representing program maturity within a domain
- **Response**: A user answer to a question, one of: Yes (fully in place), No (not in place), Partial (partially implemented at 50% weight), or N/A (excluded from scoring)
- **Checkpoint**: A JSON file storing in-progress assessment state for pause/resume capability
- **Radar_Chart**: An SVG-based spider/radar visualization showing domain scores across all 10 domains
- **Gap_Analysis**: A report section listing controls answered No or Partial, representing priority gaps to address
- **Bulk_Action**: A UI operation that sets all questions in a domain to the same answer value simultaneously

## Requirements

### Requirement 1: Start New Assessment

**User Story:** As an assessor, I want to start a new assessment by entering customer information, so that I can begin evaluating a customer's vulnerability management maturity.

#### Acceptance Criteria

1. WHEN an assessor submits the new assessment form, THE VMMA_App SHALL create a session containing the customer name, industry, assessor name, and current date
2. WHEN a new assessment is started, THE VMMA_App SHALL redirect the assessor to the questionnaire interface beginning at the first Domain
3. IF the customer name field is empty, THEN THE VMMA_App SHALL prevent form submission

### Requirement 2: Questionnaire Presentation

**User Story:** As an assessor, I want to see all questions for a domain with clear answer buttons, so that I can efficiently record responses for each control.

#### Acceptance Criteria

1. WHEN a Domain is displayed, THE VMMA_App SHALL render all questions for that Domain with numbered labels and four answer buttons (Yes, Partial, No, N/A)
2. WHEN a Domain is displayed, THE VMMA_App SHALL show the Domain name and description at the top of the question section
3. THE VMMA_App SHALL present questions across all 10 Domains containing the full set of assessment questions defined in the Assessment_Engine
4. WHEN an answer button is selected, THE VMMA_App SHALL visually highlight the selected button with a distinct color per answer type (green for Yes, yellow for Partial, red for No, gray for N/A)

### Requirement 3: Bulk Answer Operations

**User Story:** As an assessor, I want to quickly set all questions in a domain to the same answer, so that I can accelerate assessment of domains where all controls are clearly in place or absent.

#### Acceptance Criteria

1. WHEN the "Yes to All" button is clicked for a Domain, THE VMMA_App SHALL set all questions in that Domain to the Yes Response
2. WHEN the "No to All" button is clicked for a Domain, THE VMMA_App SHALL set all questions in that Domain to the No Response
3. WHEN the "Clear All" button is clicked for a Domain, THE VMMA_App SHALL remove all Responses for that Domain returning questions to their unanswered state
4. THE VMMA_App SHALL display the three Bulk_Action buttons (Yes to All, No to All, Clear All) within each Domain section header

### Requirement 4: Domain Navigation

**User Story:** As an assessor, I want to navigate between domains freely, so that I can answer questions in any order and revisit previous domains.

#### Acceptance Criteria

1. THE VMMA_App SHALL display a navigation bar showing all 10 Domain names as clickable tabs
2. WHEN a Domain tab is clicked, THE VMMA_App SHALL display the questions for that Domain while preserving all previously recorded Responses
3. THE VMMA_App SHALL visually distinguish the active Domain tab, completed Domain tabs, and incomplete Domain tabs using different color styles
4. WHEN the "Next" button is clicked, THE VMMA_App SHALL advance to the next Domain in sequence
5. WHEN the "Previous" button is clicked, THE VMMA_App SHALL return to the previous Domain in sequence
6. WHILE the assessor is on the first Domain, THE VMMA_App SHALL disable the "Previous" button
7. WHILE the assessor is on the last Domain, THE VMMA_App SHALL change the "Next" button to display "Submit Assessment"

### Requirement 5: Progress Tracking

**User Story:** As an assessor, I want to see my overall progress through the assessment, so that I know how much work remains.

#### Acceptance Criteria

1. THE VMMA_App SHALL display a progress bar showing the percentage of total questions answered across all Domains
2. WHEN a Response is recorded or cleared, THE VMMA_App SHALL immediately update the progress bar percentage
3. THE VMMA_App SHALL display the current Domain number and name (e.g., "Domain 3 of 10 — Asset Management") above the progress bar

### Requirement 6: Assessment Submission and Scoring

**User Story:** As an assessor, I want to submit the completed assessment and see the calculated maturity scores, so that I can communicate results to the customer.

#### Acceptance Criteria

1. WHEN the assessment is submitted, THE Assessment_Engine SHALL calculate a Maturity_Level for each Domain using the weighted scoring formula: Yes responses receive full weight, Partial responses receive 50% weight, No responses receive zero weight, and N/A responses are excluded from the calculation
2. WHEN the assessment is submitted, THE Assessment_Engine SHALL calculate the overall maturity score as the average of all Domain scores rounded to one decimal place
3. WHEN the assessment is submitted, THE VMMA_App SHALL save the complete assessment data (customer info, all Responses with question text, weights, and levels, Domain scores, and overall score) to a JSON file named "assessment_{CustomerName}_{Date}.json"
4. IF any Domain has zero answered questions, THEN THE VMMA_App SHALL prevent submission and alert the assessor to complete all Domains
5. WHEN the assessment is submitted successfully, THE VMMA_App SHALL display a results overlay showing the overall score and maturity level

### Requirement 7: Maturity Score Calculation

**User Story:** As an assessor, I want maturity scores calculated according to the Rapid7 methodology, so that results accurately reflect program maturity.

#### Acceptance Criteria

1. THE Assessment_Engine SHALL map weighted response percentages to Maturity_Levels as follows: 90% or above maps to level 6 (Innovating), 75%–89% maps to level 5 (Predictable), 60%–74% maps to level 4 (Standardized), 40%–59% maps to level 3 (Managed), 20%–39% maps to level 2 (Initial), below 20% maps to level 1 (Preliminary)
2. THE Assessment_Engine SHALL exclude N/A Responses from both the numerator and denominator of the score calculation
3. WHEN all Responses in a Domain are N/A, THE Assessment_Engine SHALL assign that Domain a Maturity_Level of 1 (Preliminary)
4. THE Assessment_Engine SHALL apply question weights to the scoring calculation where higher-weight questions contribute proportionally more to the Domain score

### Requirement 8: HTML Report Generation

**User Story:** As an assessor, I want a professional HTML report generated from the assessment results, so that I can share findings with the customer.

#### Acceptance Criteria

1. WHEN an assessment is submitted, THE Report_Generator SHALL produce an HTML report file named "assessment_{CustomerName}_{Date}_report.html"
2. THE Report_Generator SHALL include an overall maturity score card showing the numeric score, maturity level name, and a recommended target of "Predictable (5.0)"
3. THE Report_Generator SHALL include a Radar_Chart visualizing all 10 Domain scores on a hexagonal grid scaled from 1 to 6
4. THE Report_Generator SHALL include a domain scores table showing each Domain name, score bar, maturity level badge, and yes/total count with percentage
5. THE Report_Generator SHALL include a Gap_Analysis section listing all questions answered No or Partial, grouped by Domain and sorted from lowest to highest Domain score
6. THE Report_Generator SHALL include a prioritized recommendations section with domain-specific improvement suggestions, ordered from lowest to highest Domain score
7. THE Report_Generator SHALL include customer metadata (name, industry, assessor, date) in the report header

### Requirement 9: Report Viewing and PDF Export

**User Story:** As an assessor, I want to view generated reports in the browser and export them as PDF, so that I can deliver findings in the customer's preferred format.

#### Acceptance Criteria

1. WHEN the "View Full Report" link is clicked, THE VMMA_App SHALL render the generated HTML report in the browser
2. WHEN the "Download PDF" link is clicked, THE VMMA_App SHALL serve a print-optimized version of the report with CSS print styles and trigger the browser's print dialog
3. THE VMMA_App SHALL display previously generated assessments on the home page with links to view the report and download as PDF
4. THE Report_Generator SHALL include print-friendly CSS that switches to white background, dark text, and appropriate borders for PDF output

### Requirement 10: Pause and Resume Assessment

**User Story:** As an assessor, I want to pause an in-progress assessment and resume it later, so that I can complete assessments across multiple sessions.

#### Acceptance Criteria

1. WHEN an in-progress assessment exists as a Checkpoint file, THE VMMA_App SHALL display it on the home page with a "Resume" link
2. WHEN the assessor clicks "Resume" on a Checkpoint, THE VMMA_App SHALL restore all previously recorded Responses and navigate to the first incomplete Domain
3. WHEN an assessment is submitted successfully, THE VMMA_App SHALL delete the corresponding Checkpoint file
4. THE VMMA_App SHALL store Checkpoint data as JSON containing customer information, completed Domain responses, and the current Domain state

### Requirement 11: Assessment Data Persistence

**User Story:** As an assessor, I want assessment data stored as JSON files, so that results are portable and accessible outside the application.

#### Acceptance Criteria

1. THE VMMA_App SHALL store completed assessment results as JSON files in the application data directory
2. THE VMMA_App SHALL include all question-level Response data in the JSON output including question text, answer value, maturity level mapping, and weight
3. THE VMMA_App SHALL use the naming convention "assessment_{CustomerName}_{Date}.json" with spaces in customer name replaced by underscores
4. THE VMMA_App SHALL persist the generated HTML report alongside the JSON file using the naming convention "assessment_{CustomerName}_{Date}_report.html"

### Requirement 12: Landing Page and Assessment Management

**User Story:** As an assessor, I want a home page that shows all previous assessments and allows starting new ones, so that I can manage multiple customer assessments.

#### Acceptance Criteria

1. THE VMMA_App SHALL display a landing page with a form to start a new assessment and lists of previous assessments and in-progress checkpoints
2. THE VMMA_App SHALL sort previous assessments by most recently modified first
3. WHEN previous assessments exist, THE VMMA_App SHALL provide "View Report" and "PDF" links for each assessment
4. WHEN checkpoint files exist, THE VMMA_App SHALL provide a "Resume" link for each in-progress assessment

---

## Planned Improvements (Future)

The following requirements document planned enhancements to be implemented after the initial release. They are not part of the current working application.

### Requirement 13: Multi-User Authentication (Future)

**User Story:** As an organization, I want multiple assessors to log in with their own accounts, so that assessments are attributed to specific users and access is controlled.

#### Acceptance Criteria

1. WHEN an assessor navigates to the VMMA_App, THE VMMA_App SHALL require authentication before granting access to assessments
2. THE VMMA_App SHALL support user registration with email, display name, and password
3. WHEN an assessor creates an assessment, THE VMMA_App SHALL associate that assessment with the authenticated user
4. THE VMMA_App SHALL restrict assessment viewing to the user who created it and any designated administrators

### Requirement 14: Database Backend (Future)

**User Story:** As an administrator, I want assessment data stored in a database rather than flat JSON files, so that data is queryable, scalable, and supports concurrent access.

#### Acceptance Criteria

1. THE VMMA_App SHALL store assessment data in a relational database (SQLite for single-instance, PostgreSQL for multi-instance deployments)
2. THE VMMA_App SHALL provide a data migration utility to import existing JSON assessment files into the database
3. THE VMMA_App SHALL support concurrent assessment sessions without data conflicts
4. THE VMMA_App SHALL maintain an audit trail of assessment creation and modification timestamps

### Requirement 15: Assessment Comparison Reports (Future)

**User Story:** As an assessor, I want to compare a customer's current assessment against a previous one, so that I can demonstrate maturity progress over time.

#### Acceptance Criteria

1. WHEN two assessments for the same customer exist, THE Report_Generator SHALL produce a comparison report showing score changes per Domain
2. THE Report_Generator SHALL display a dual Radar_Chart overlay showing previous and current assessment scores
3. THE Report_Generator SHALL highlight Domains where maturity improved, regressed, or remained unchanged
4. THE Report_Generator SHALL calculate an overall maturity trend (improving, stable, declining) based on score deltas

### Requirement 16: Custom Question Sets (Future)

**User Story:** As an assessor, I want to customize the question set for specific customers or industries, so that assessments are relevant to the customer's regulatory and operational context.

#### Acceptance Criteria

1. THE VMMA_App SHALL support loading custom question sets from configuration files
2. WHEN a custom question set is loaded, THE VMMA_App SHALL validate that all questions have required fields (text, level, weight)
3. THE VMMA_App SHALL allow adding supplementary questions to existing Domains without modifying the base question set
4. THE VMMA_App SHALL allow disabling specific questions for a given assessment

### Requirement 17: Automated Scoring from InsightVM Data (Future)

**User Story:** As an assessor, I want to pre-populate certain assessment answers using data from Rapid7 InsightVM, so that assessments reflect actual tool configuration rather than relying solely on interview responses.

#### Acceptance Criteria

1. WHERE InsightVM integration is configured, THE VMMA_App SHALL query InsightVM data to suggest answers for discovery and scanning questions
2. WHERE InsightVM integration is configured, THE VMMA_App SHALL pre-populate scan coverage, authenticated scan status, and scan frequency metrics
3. WHEN InsightVM data suggests an answer, THE VMMA_App SHALL display the suggested answer with a data-source indicator allowing the assessor to override
4. THE VMMA_App SHALL clearly distinguish auto-populated answers from manually entered answers in the report

### Requirement 18: Executive Summary Export (Future)

**User Story:** As an assessor, I want to generate a concise executive summary suitable for C-level stakeholders, so that leadership can understand maturity posture without reading the full report.

#### Acceptance Criteria

1. THE Report_Generator SHALL produce an executive summary as a single-page view containing overall score, top 3 gaps, and top 3 recommendations
2. THE Report_Generator SHALL use non-technical language appropriate for executive audiences in the executive summary
3. THE Report_Generator SHALL include a maturity roadmap showing recommended next steps to reach the target level
4. WHEN the executive summary is exported, THE Report_Generator SHALL format it for both HTML viewing and PDF printing

### Requirement 19: Assessment Templates and Presets (Future)

**User Story:** As an assessor, I want to start an assessment from a template pre-configured for specific industries or frameworks, so that I can streamline recurring assessment types.

#### Acceptance Criteria

1. THE VMMA_App SHALL support saving a completed assessment as a reusable template
2. WHEN a template is selected, THE VMMA_App SHALL pre-populate customer information fields and domain configurations from the template
3. THE VMMA_App SHALL provide built-in presets for common industry verticals (Financial Services, Healthcare, Retail, Manufacturing)
4. THE VMMA_App SHALL allow assessors to create, edit, and delete custom templates
