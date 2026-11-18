# MASTER DEVELOPMENT PROMPT
# DEPENDENCY WATCH — Advanced Software Supply Chain Security Platform

## 1. PROJECT OVERVIEW

Build a complete, production-quality software security platform named **DEPENDENCY WATCH**.

Tagline: **"Know Your Dependencies. Control Your Risks."**

Dependency Watch is an enterprise-grade software supply chain security platform that scans software services, discovers direct and transitive dependencies, identifies known vulnerabilities, evaluates security risks, recommends fixes and tracks vulnerabilities until resolution.

The product should feel like a premium cybersecurity and advanced engineering technology platform.

This is not a simple dashboard or CRUD application. It must be a fully functional, integrated software product with a distinctive visual identity and working backend functionality.

Follow the supplied Acko SDE Intern Product Build problem statement.

Implement all ten mandatory requirements:

1. Service inventory.
2. Versions and ranges.
3. Vulnerability feed.
4. Vulnerability matching.
5. Risk prioritisation.
6. Fix recommendations.
7. Findings tracking.
8. Changes over time.
9. User interface.
10. Metrics and runnable application.

---

# 2. DESIGN DIRECTION — STRICTLY FOLLOW

Use the attached Velocitus website screenshot as the primary visual reference.

Recreate its design philosophy for a cybersecurity engineering product, not its robotics content.

### Visual identity

The interface must have:

- Deep black backgrounds.
- Dark charcoal surfaces.
- Strong crimson and red accents.
- Selective red-to-magenta gradients in major visual sections.
- Futuristic geometric wireframe patterns.
- Technical grid backgrounds.
- Large futuristic typography.
- Strong white text contrast.
- Dramatic asymmetric layouts.
- Sharp, sophisticated interface elements.
- Subtle glowing red highlights only where appropriate.

### Colour palette

Use these design tokens consistently:

- Main background: #080808
- Secondary background: #111111
- Panel background: #171717
- Elevated surface: #202020
- Border: #303030
- Primary red: #E50932
- Crimson: #C8102E
- Magenta accent: #A90052
- White: #F5F5F5
- Secondary text: #A4A4A4
- Muted text: #686868
- Critical status: #FF3030
- Success status: #38B779

Use gradients selectively, especially for the hero area and major visual accents. Do not cover every card or component with gradients.

### Typography

Use:
- Space Grotesk for headings.
- Inter for interface text.
- JetBrains Mono for package versions, vulnerability IDs, technical identifiers and terminal output.

Large headings should be bold, futuristic and editorial.

### Visual restrictions

DO NOT use:
- Purple/blue SaaS gradients.
- Generic AI dashboard templates.
- Excessive rounded cards.
- Glassmorphism everywhere.
- Random floating blobs.
- Cartoon illustrations.
- Unnecessary 3D decorations.
- Repetitive four-card dashboard layouts.
- Generic admin panel designs.

The result should resemble a premium engineering and cybersecurity technology website.

---

# 3. BRANDING AND APPLICATION STRUCTURE

Product name: DEPENDENCY WATCH

Logo concept:
A custom geometric shield combined with a dependency/network symbol.

Logo text:
DEPENDENCY WATCH

Small brand descriptor:
SOFTWARE SUPPLY CHAIN INTELLIGENCE

Use a professional application layout with:

- Collapsible left sidebar.
- Main workspace.
- Top navigation.
- Global search.
- Notifications.
- Profile menu.
- Breadcrumb navigation.

### Main navigation

1. Overview
2. Service Registry
3. Dependency Explorer
4. Vulnerability Centre
5. Findings Management
6. Security Analytics
7. Activity Logs
8. Settings

All navigation items must work.

---

# 4. HOMEPAGE / OVERVIEW DASHBOARD

Create a visually impressive first screen.

The dashboard should have a distinctive hero section inspired by the supplied Velocitus reference.

### Hero section

Use a large headline:

"YOUR CODE.
YOUR DEPENDENCIES.
YOUR SECURITY."

Supporting description:

"Gain complete visibility into your software supply chain. Discover vulnerabilities, identify exposed services and resolve security risks before they become production incidents."

Include two primary actions:

- INITIATE SECURITY SCAN
- EXPLORE DEPENDENCIES

Add a technical wireframe or dependency-network visual on the right side.

The hero should have:
- Black technical grid.
- Red geometric network lines.
- Dramatic red accent lighting.
- Subtle animated background elements.
- A visually dominant headline.

### Security overview

Display:

- Total registered services.
- Total packages scanned.
- Total vulnerabilities.
- Critical vulnerabilities.
- Open findings.
- Resolved findings.
- Overdue findings.

Use large typography and custom data visualisations instead of generic statistic cards.

### Additional dashboard sections

1. Vulnerability severity distribution.
2. Security risk trend.
3. Most affected services.
4. Recently discovered vulnerabilities.
5. Recent remediation activity.
6. Services requiring immediate attention.
7. Latest scan information.

Every statistic must come from actual application data.

---

# 5. SERVICE REGISTRY

Build a complete service management module.

The assignment provides eight services in its starter kit.

Display services in a professional inventory interface.

Each service should contain:

- Service name.
- Description.
- Owner.
- Programming ecosystem.
- Business criticality.
- Internet exposure.
- Dependency count.
- Vulnerability count.
- Current risk level.
- Last scanned timestamp.

### Functionalities

- Register a service.
- View service details.
- Edit service metadata.
- Search services.
- Filter by technology.
- Filter by risk.
- Scan an individual service.
- View its dependency inventory.

Support both npm and Python dependency ecosystems.

---

# 6. DEPENDENCY EXPLORER

This must be one of the most visually impressive features.

Build an interactive dependency graph.

Show the relationship between:

Service → Direct dependency → Transitive dependency → Vulnerable package.

### Visual representation

- Normal dependencies: white or grey nodes.
- Vulnerable dependencies: red nodes.
- Critical vulnerabilities: bright crimson nodes.
- Connections: thin technical lines.
- Selected node: animated red outline.

### Interactions

- Zoom in and out.
- Pan around the graph.
- Select individual nodes.
- Search packages.
- Expand dependency relationships.
- Display package details in a side panel.
- Highlight the path leading to a vulnerable transitive dependency.

Show the dependency chain explaining how an indirectly installed package enters a service.

Use a graph visualisation library such as React Flow.

Do not fabricate dependency relationships. Build the graph from actual scanner output.

---

# 7. DEPENDENCY SCANNER

Build the actual dependency scanning engine.

It must read dependency files from the provided starter kit.

Support:

### Node.js
- package.json
- package-lock.json

### Python
- requirements.txt
- Supported Python dependency lock files where present.

The scanner should:

1. Identify registered services.
2. Locate dependency manifests.
3. Parse installed package versions.
4. Resolve direct dependencies.
5. Identify transitive dependencies using available lockfile information.
6. Store package relationships.
7. Save scan results.
8. Detect dependency changes between scans.

Do not pretend to resolve transitive dependencies when the supplied files do not contain enough information.

### Scan Command Centre

Create a dedicated scanning interface.

Show:

- Current scanning service.
- Files being processed.
- Number of packages inspected.
- Vulnerabilities discovered.
- Scan progress.
- Scan duration.
- Scan completion status.

Use actual backend progress events where possible.

---

# 8. VULNERABILITY CENTRE

Integrate the supplied mock OSV vulnerability feed.

Do not replace the provided feed with invented vulnerability records.

Read advisory information including:

- Vulnerability ID.
- Package ecosystem.
- Package name.
- Affected version ranges.
- Fixed versions.
- Severity.
- Advisory details.

### Vulnerability matching

Compare installed package versions with the affected version ranges.

Support correct version comparisons for npm and Python packages.

Avoid simplistic string comparison.

Repeated feed imports must not generate duplicate vulnerability records.

### Findings table

Display:

- Advisory ID.
- Package.
- Affected service.
- Installed version.
- Affected version range.
- Fixed version.
- Severity.
- Priority.
- Status.

Add search, sorting and filtering.

---

# 9. RISK PRIORITISATION ENGINE

Build a deterministic risk prioritisation system.

Consider:

1. Vulnerability severity.
2. Service business criticality.
3. Internet exposure.
4. Availability of a fixed version.
5. Upgrade complexity where information is available.

Create a transparent scoring methodology.

Display why a particular vulnerability received its priority.

Do not invent severity scores or claim that a heuristic is an official CVSS score.

Show:

- Critical.
- High.
- Medium.
- Low.

The risk engine should produce explainable results.

---

# 10. FIX RECOMMENDATIONS

For each vulnerability, display:

- Installed package version.
- Affected version range.
- Recommended fixed version.
- Upgrade complexity.
- Whether a direct fix is available.
- Recommended remediation action.

Example:

Package: Lodash
Installed: 4.17.20
Fixed: 4.17.21
Status: Vulnerable

Recommendation:
Upgrade to a verified fixed version.

Never recommend a version that the vulnerability feed does not identify as fixed.

---

# 11. FINDINGS MANAGEMENT

Build a complete vulnerability lifecycle workflow.

Finding statuses:

- Open.
- In Progress.
- Resolved.

Each finding should contain:

- Vulnerability ID.
- Affected service.
- Package name.
- Severity.
- Priority.
- Assigned owner.
- Due date.
- Creation timestamp.
- Last updated timestamp.
- Resolution information.

### Actions

- Assign finding to an owner.
- Change status.
- Set due date.
- Add remediation notes.
- View finding history.
- Identify overdue findings.
- Resolve findings after successful verification.

A finding should not automatically become resolved just because a developer clicks a button.

Recheck the relevant dependency state before confirming resolution.

---

# 12. CHANGES OVER TIME

Implement historical tracking.

The system must detect:

- Newly discovered vulnerabilities.
- Resolved vulnerabilities.
- Reappearing vulnerabilities.
- Updated package versions.
- Changed dependency relationships.

Create a chronological activity timeline.

Display before-and-after information for dependency changes.

---

# 13. SECURITY ANALYTICS

Create an analytics section containing:

- Vulnerabilities by severity.
- Vulnerabilities by service.
- Open findings over time.
- Resolved findings over time.
- Average resolution time.
- Overdue findings.
- Total packages scanned.
- Most vulnerable services.

Use visually distinctive charts that match the black-and-red brand.

All charts must use real database values.

---

# 14. ACTIVITY LOGS

Record important events:

- Service registration.
- Dependency scan started.
- Dependency scan completed.
- New vulnerability detected.
- Finding assigned.
- Finding status changed.
- Finding resolved.
- Vulnerability reappeared.

Display timestamps and related entities.

---

# 15. WEBHOOK INTEGRATION

Use the webhook receiver provided by the starter kit.

Send relevant notifications when:

- New critical vulnerabilities are discovered.
- High-priority findings are created.
- A finding is resolved.
- A finding becomes overdue.

Use the actual receiver contract and verify delivery.

Do not invent webhook endpoints.

---

# 16. BACKEND ARCHITECTURE

Recommended technology stack:

Frontend:
- React.
- Vite.
- TypeScript.
- Tailwind CSS.
- Framer Motion.
- React Flow.
- Recharts or an equivalent charting library.
- Lucide React icons.

Backend:
- Python.
- FastAPI.
- SQLAlchemy.
- Pydantic.

Database:
- SQLite for a simple, runnable local application.

Testing:
- Pytest.
- API integration tests.
- Frontend interaction tests.

Containerisation:
- Docker Compose.

Keep the frontend and backend modular.

Suggested architecture:

```
frontend/
  src/
    components/
    layouts/
    pages/
    features/
      dashboard/
      services/
      dependencies/
      vulnerabilities/
      findings/
      analytics/
    hooks/
    services/
    types/
    styles/

backend/
  app/
    api/
    core/
    models/
    schemas/
    services/
      scanner/
      vulnerability/
      versioning/
      risk_engine/
      remediation/
      analytics/
    database/
    tests/
```

---

# 17. DATABASE DESIGN

Create appropriate relational models.

Suggested tables:

1. services
2. dependencies
3. dependency_relationships
4. vulnerability_advisories
5. vulnerability_affected_ranges
6. findings
7. finding_assignments
8. scan_sessions
9. scan_results
10. activity_logs

Use appropriate primary keys, foreign keys, indexes and uniqueness constraints.

Avoid duplicate advisories, packages and findings.

Preserve historical information when dependencies change.

---

# 18. UI/UX INTERACTIONS

Implement:

- Smooth page transitions.
- Animated number counters.
- Hover interactions.
- Interactive dependency graph.
- Scan progress animation.
- Search command palette.
- Toast notifications.
- Confirmation dialogs.
- Loading skeletons.
- Empty states.
- Error states.
- Responsive layouts.

Animations must be subtle and professional.

Do not sacrifice application performance for visual effects.

---

# 19. QUALITY AND TESTING

Implement tests for:

1. Dependency manifest parsing.
2. Version range matching.
3. Direct dependency detection.
4. Transitive dependency detection.
5. Vulnerability matching.
6. Duplicate advisory prevention.
7. Risk prioritisation.
8. Finding lifecycle.
9. Finding resolution verification.
10. Historical change detection.
11. API functionality.
12. Frontend workflows.

Test actual edge cases.

Do not report tests as passing without executing them.

---

# 20. PROJECT DOCUMENTATION AND SUBMISSION

Create:

- README.md
- PLAN.md
- PROGRESS.md
- DECISIONS.md
- REVIEW.md
- tests/
- transcripts/

Document:

- Project architecture.
- Database design.
- Setup instructions.
- API endpoints.
- Scanner functionality.
- Vulnerability matching logic.
- Risk scoring methodology.
- Known limitations.
- Test results.

The application must start using a single documented command.

Use the Docker or Podman setup specified by the assignment.

Preserve the provided starter kit and its original functionality.

---

# 21. IMPORTANT DEVELOPMENT RULES

1. First inspect the existing project files and starter kit.
2. Understand the existing service data and vulnerability feed.
3. Do not overwrite or discard starter kit files.
4. Do not invent service names, package versions or vulnerability records.
5. Build actual backend functionality before polishing secondary animations.
6. Connect every UI component to real backend data.
7. Do not create buttons that do nothing.
8. Do not use hardcoded dashboard statistics.
9. Do not simulate successful scans without running the scanner.
10. Keep code modular, readable and explainable.
11. Run tests after implementing each major module.
12. Maintain Git commits throughout development.
13. Save AI coding session transcripts as required by the assignment.
14. Keep track of incomplete requirements honestly.

---

# 22. SIX-HOUR IMPLEMENTATION PRIORITY

Prioritise work according to the assignment deadline.

Phase 1:
- Project setup.
- Architecture.
- Database.
- Service inventory.

Phase 2:
- Dependency scanning.
- Version parsing.
- Vulnerability feed integration.
- Vulnerability matching.

Phase 3:
- Risk prioritisation.
- Findings management.
- Fix recommendations.

Phase 4:
- Dashboard.
- Dependency Explorer.
- Analytics.
- Webhook integration where time permits.

Phase 5:
- Testing.
- README.
- Decision log.
- Final verification.

All mandatory requirements should be prioritised over optional animations and decorative features.

If time is limited, implement smaller but genuinely working versions of the mandatory features rather than leaving major requirements as visual placeholders.

---

# 23. FINAL EXPECTATION

Deliver a complete, working product called DEPENDENCY WATCH.

It must have the visual quality of a premium futuristic cybersecurity technology website, inspired by the supplied Velocitus design reference.

The application should be:

- Visually distinctive.
- Technically functional.
- Properly structured.
- Tested.
- Easy to run.
- Easy to demonstrate.
- Easy to explain to experienced software engineers.

The most important principle:

**Build a real security product with an exceptional visual identity, not a beautiful mockup with non-functional buttons.**

Start by inspecting the starter kit, understanding the data and producing the implementation plan before writing application code.
