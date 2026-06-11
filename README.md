# DF-IR_Group_Project
---

## 🤖 AI Threat Analysis Engine (New Feature)

An automated security incident correlation module has been integrated into the backend architecture. This engine analyzes system log bursts on the fly, cross-references security anomalies, and generates deterministic mitigation roadmaps using **Gemini 2.5 Flash**.

* **Module Workspace**: Located entirely within the isolated [`/AI Threat Analysis Integration`](./AI%20Threat%20Analysis%20Integration/) directory.
* **Core Integrations**: Official `@google/genai` SDK with strict JSON schemas and exponential backoff error-handling.
* **Security Guardrails**: Features built-in structural injection isolation and a rule-based offline fallback mechanism.

### Quick Start Requirement
To activate this module, add your Google AI Studio API token to your root `.env` configuration file:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```

For complete implementation architecture, database attachment procedures, and curl attack simulation matrices, check out the full [AI Threat Module Documentation](./AI%20Threat%20Analysis%20Integration/README.md).

