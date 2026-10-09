# UI/UX Design Brief: Cookie-Oracle Dashboard

## Visual Style
Theme: Dark Hacker Terminal Aesthetic
Primary Color: #00FF41 (neon green terminal text)
Secondary Colors:
- Background: #0F0F0F (dark)
- Cards: #1A1A1A
- Borders: #333333
- Accent Red (for high-risk): #FF073A
- Accent Yellow (for warnings): #FFAA00

Typography:
- Font Family: JetBrains Mono (code-style feel)
- Headings: Bold, 24px
- Body Text: Medium, 16px
- Code Snippets: Italicized Courier New

## Component Style Guide
- Buttons: Rounded corners (4px), solid fill
 - Primary: Neon green background
 - Danger: Red background
- Cards: Subtle shadow, hover glow effect
- Tables: Zebra-striped rows, fixed headers
- Risk Indicators: Colored badges
 - High = Red
 - Medium = Yellow
 - Low = Green

## Screen Mockups (Textual Description)
1. Home Screen:
 - Large input box ("Paste your cookie here...")
 - Upload area ("Drag & Drop file here")
 - Example cookies section ("Try these samples:")
 - Footer with quick links

2. Result Screen:
 - Top bar: Platform name + risk score badge
 - Grid layout: Status panel | Flags panel | Meta panel
 - Exploitation matrix table below
 - Tabs at bottom for timeline/download options

3. History Screen:
 - Table view of past reports
 - Columns: Date | Platform | Risk Score | Actions
 - Search/filter bar at top

4. Settings Screen:
 - Toggle switches for features
 - Input fields for API keys
 - Save/Cancel buttons aligned right