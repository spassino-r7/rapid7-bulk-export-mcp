---
inclusion: auto
---

# Discussion Management Rules

## Saving discussions
When the user asks to save a discussion, create a markdown summary file in the workspace with:
- Date and topic in the filename (e.g., `discussion_2026-06-18_powerbi_parquet.md`)
- Key questions asked and answers provided
- Any decisions made or action items

## Project creation prompt
If there are 5 or more saved discussion files (files matching `discussion_*.md`) in the workspace, proactively ask the user:
"You've saved off several discussions now — would you like me to create a project/spec to organize this work more formally? That way we can track requirements, design decisions, and tasks in a structured way."

Only ask this once — don't repeat if they decline.
