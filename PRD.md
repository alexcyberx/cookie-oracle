# Product Requirements Document (PRD): Cookie-Oracle
**Tool Description:** A powerful, CLI-first session intelligence engine that analyzes cookies, detects their source platform, evaluates session validity, privilege levels, and generates exploitation matrices.

## 1. Overview
Cookie-Oracle is an advanced security tool designed to extract intelligence from session cookies without requiring login. It identifies the owning platform, checks if the session is still active, determines user privilege levels, and provides a full report on risks and exploitation possibilities.

Target Audience:
- Penetration testers
- Red team operators
- CTF players
- Security researchers

## 2. Goals
- Provide instant insight into any given cookie
- Detect if a cookie is expired/fake/real without accessing the target site
- Identify privilege levels (guest/user/admin/root)
- Generate exploitation matrices (hijacking, CSRF, fixation, replay)
- Platform detection (Instagram, Google, GitHub, etc.)
- Risk scoring (0-100) with visual indicators

## 3. Features (MVP)
| Feature ID | Feature Name | Priority |
|------------|------------------------|----------|
| F-01 | Session Status Check | Must Have|
| F-02 | Domain Reputation Scan | Should Have|
| F-03 | Privilege Level Detection | Must Have|
| F-04 | Session Binding Detection | Should Have|
| F-05 | Activity Timeline Reconstruction | Could Have|
| F-06 | Vulnerability Suggestions | Must Have|
| F-07 | Platform Detector | Must Have|
| F-08 | Cookie Metadata Extractor | Must Have|
| F-09 | Exploitation Matrix | Must Have|
| F-10 | Risk Scoring Dashboard | Must Have|

## 4. User Stories
- As a pentester, I want to know if a stolen cookie gives admin access so I can plan my next move.
- As a red teamer, I want to detect which platform a cookie belongs to so I can search for known exploits.
- As a CTF player, I want a ranked list of exploitable cookies so I can focus on high-value targets.

## 5. Assumptions
- Cookies come from browser exports, proxy captures, or manual inputs.
- Target platforms have predictable cookie naming patterns.
- Basic HTTP probing is allowed (does NOT require active session use)

## 6. Metrics
- Accuracy of platform/platform detection (>90%)
- Number of successful session validations
- False positive/negative rates on privilege detection
- Time-to-report (must be < 5 seconds for single cookie)