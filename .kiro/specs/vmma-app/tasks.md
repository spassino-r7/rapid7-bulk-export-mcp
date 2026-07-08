# Implementation Plan: VMMA Web Application

## Overview

This plan restructures the existing VMMA prototype into a proper Python project layout, adds comprehensive property-based and unit testing (Hypothesis + pytest), implements error handling improvements identified in the design, and ensures full coverage of requirements 1–12. The existing code is functional — tasks focus on project hygiene, test coverage, validation hardening, and gap fixes.

## Tasks

- [ ] 1. Project restructuring and setup
  - [ ] 1.1 Create proper project layout and configuration files
    - Create `requirements.txt` with pinned dependencies (Flask, pytest, hypothesis, pytest-cov)
    - Create `README.md` with project overview, setup instructions, and usage guide
    - Create `tests/` directory with `__init__.py` and `conftest.py`
    - Add `.gitignore` for Python projects (venv, __pycache__, *.pyc, .env)
    - _Requirements: 11.1, 11.2_

  - [ ] 1.2 Create shared test fixtures and Hypothesis generators in `tests/conftest.py`
    - Implement `valid_response()` strategy: generates `{question: str, answer: sampled_from(['y','n','p','u']), level: integers(1,6), weight: sampled_from([1,2])}`
    - Implement `valid_domain_responses()` strategy: lists of valid_response dicts (min_size=1)
    - Implement `valid_customer()` strategy: dict with name, industry, assessor, date fields
    - Implement `valid_results()` strategy: full assessment results dict with customer, 10 domains, scores
    - Create Flask test client fixture for integration tests
    - _Requirements: 6.1, 7.1, 7.2, 8.1_

- [ ] 2. Scoring engine property tests and hardening
  - [ ] 2.1 Add input validation to `calculate_domain_score` in `maturity_assessment.py`
    - Validate that responses is a list and each entry has required keys (answer, weight)
    - Filter out responses with invalid answer values (not in y, n, p, u)
    - Return score 1 for empty list or None input gracefully
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

  - [ ]* 2.2 Write property test for scoring algorithm (Property 1)
    - **Property 1: Scoring algorithm maps weighted percentages to correct maturity levels**
    - **Validates: Requirements 6.1, 7.1, 7.4**

  - [ ]* 2.3 Write property test for N/A exclusion (Property 2)
    - **Property 2: N/A responses do not affect scoring**
    - **Validates: Requirements 7.2, 7.3**

  - [ ]* 2.4 Write property test for overall score calculation (Property 3)
    - **Property 3: Overall score is the rounded average of domain scores**
    - **Validates: Requirements 6.2**

  - [ ]* 2.5 Write unit tests for scoring edge cases in `tests/test_scoring.py`
    - Test all-yes → 6, all-no → 1, all-N/A → 1
    - Test boundary values at each threshold (20%, 40%, 60%, 75%, 90%)
    - Test mixed responses with weight=2 questions
    - Test empty response list returns 1
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [ ] 3. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Report generation property tests
  - [ ] 4.1 Write property test for report content sections (Property 7)
    - **Property 7: Generated HTML report contains all required content sections**
    - **Validates: Requirements 8.2, 8.4, 8.7**

  - [ ]* 4.2 Write property test for gap analysis completeness (Property 8)
    - **Property 8: Gap analysis includes all No and Partial responses**
    - **Validates: Requirements 8.5**

  - [ ]* 4.3 Write property test for recommendation ordering (Property 9)
    - **Property 9: Recommendations are ordered by ascending domain score**
    - **Validates: Requirements 8.6**

  - [ ]* 4.4 Write property test for radar chart data points (Property 10)
    - **Property 10: Radar chart contains correct number of data points**
    - **Validates: Requirements 8.3**

  - [ ]* 4.5 Write unit tests for report generation in `tests/test_report_generation.py`
    - Test that PDF route includes print CSS styles and auto-print script
    - Test report contains recommended target "Predictable (5.0)"
    - Test report footer includes generation timestamp
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 9.4_

- [ ] 5. Data persistence and navigation property tests
  - [ ] 5.1 Write property test for filename convention (Property 11)
    - **Property 11: Filename generation follows naming convention**
    - **Validates: Requirements 6.3, 11.3**

  - [ ]* 5.2 Write property test for checkpoint round-trip (Property 12)
    - **Property 12: Checkpoint data round-trip**
    - **Validates: Requirements 10.4**

  - [ ]* 5.3 Write property test for resume domain index (Property 13)
    - **Property 13: Resume navigates to first incomplete domain**
    - **Validates: Requirements 10.2**

  - [ ]* 5.4 Write property test for submission blocking (Property 14)
    - **Property 14: Submission is blocked when any domain has zero responses**
    - **Validates: Requirements 6.4**

  - [ ]* 5.5 Write property test for progress percentage (Property 15)
    - **Property 15: Progress percentage calculation**
    - **Validates: Requirements 5.1**

- [ ] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Error handling improvements in Flask app
  - [ ] 7.1 Add try/except around file I/O in `/api/submit` route
    - Wrap JSON file write and HTML report write in try/except
    - Return `{success: false, error: "message"}` on filesystem errors
    - Log the exception for debugging
    - _Requirements: 6.3, 11.1_

  - [ ] 7.2 Add checkpoint JSON validation in `/resume` route
    - Wrap checkpoint load in try/except for JSONDecodeError and KeyError
    - Validate checkpoint has required keys (customer, completed_domains)
    - Redirect to index with appropriate handling on invalid checkpoint
    - _Requirements: 10.1, 10.2_

  - [ ] 7.3 Sanitize customer name for filename safety
    - Strip characters beyond spaces that are problematic for filenames (/, \, :, *, ?, ", <, >, |)
    - Replace spaces with underscores in filename generation
    - Ensure empty/whitespace-only names are rejected at the route level
    - _Requirements: 1.3, 11.3_

- [ ] 8. Integration tests for Flask routes
  - [ ]* 8.1 Write integration tests in `tests/test_app_routes.py`
    - Test full workflow: POST /new → GET /assess → POST /api/submit → GET /view
    - Test resume workflow: create checkpoint file → GET /resume → verify session
    - Test landing page lists existing assessments and checkpoints
    - Test /resume with missing file redirects to index
    - Test /view with missing report returns 404 or redirects
    - Test POST /new with empty customer name behavior
    - _Requirements: 1.1, 1.2, 1.3, 9.1, 9.3, 10.1, 10.2, 10.3, 12.1, 12.2, 12.3, 12.4_

- [ ] 9. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- The existing prototype code (vmma_app.py, maturity_assessment.py, generate_report.py, templates/) is functional — tasks focus on hardening, testing, and project structure
- All property tests use Hypothesis with `@settings(max_examples=100)` minimum
- Each property test file includes a tag comment: `# Feature: vmma-app, Property {N}: {title}`

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "2.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "2.4", "2.5"] },
    { "id": 3, "tasks": ["4.1", "4.2", "4.3", "4.4", "4.5", "5.1", "5.2", "5.3", "5.4", "5.5"] },
    { "id": 4, "tasks": ["7.1", "7.2", "7.3"] },
    { "id": 5, "tasks": ["8.1"] }
  ]
}
```
