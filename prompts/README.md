# /prompts — Version-Controlled Prompt Templates

**OWNER: All hires (each owns their team's subfolder)**  
**RULE: Every prompt change is a PR. No exceptions.**

---

## Why This Folder Exists

Prompts are the single most important determinant of agent quality on 7–8B models.
They must be version-controlled, reviewed, and A/B tested — not hardcoded in Python files.

---

## Rules for Prompt Files

1. **One file per agent per version** — `exploitation_agent_v1.md`, `exploitation_agent_v2.md`
2. **Never delete old versions** — rename to `_deprecated` if superseded
3. **Every prompt file must include a header:**

```
# Prompt: [Agent Name]
# Version: vX.X
# Author: [name]
# Date: [date]
# Change: [what changed from previous version and why]
# Tested on: [which CVEs / targets]
# Result: [ESR/PSR delta from previous version]
```

4. **Red Team prompts must include** a line instructing the agent to always reference retrieved CVE data before proposing an attack vector
5. **Blue Team prompts must include** a line instructing the agent to always produce minimal diffs — smallest possible change that fixes the vulnerability

---

## Folder Structure

```
/prompts/
├── README.md
├── /red_team/
│   ├── supervisor_v1.md
│   ├── recon_agent_v1.md
│   ├── exploitation_agent_v1.md
│   └── verification_agent_v1.md
└── /blue_team/
    ├── supervisor_v1.md
    ├── log_analysis_agent_v1.md
    ├── root_cause_agent_v1.md
    ├── patch_generation_agent_v1.md
    └── patch_validation_agent_v1.md
```