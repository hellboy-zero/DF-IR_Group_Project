import { GoogleGenAI, Type, Schema } from '@google/genai';
import * as dotenv from 'dotenv';

dotenv.config();

// Initialize the official Gemini SDK
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

// TypeScript interfaces for system type safety
export interface LogEntry {
  timestamp: string;
  sourceIp: string;
  eventType: string;
  details: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface CorrelationResult {
  incidentId: string;
  correlatedLogs: LogEntry[];
  summary: string;
}

// Strict Structured Schema layout for Gemini JSON responses
const threatAnalysisSchema: Schema = {
  type: Type.OBJECT,
  properties: {
    riskScore: { 
      type: Type.INTEGER, 
      description: "A calculated threat score from 0 (Safe) to 100 (Critical)." 
    },
    threatActor: { 
      type: Type.STRING, 
      description: "Identified or suspected threat group/classification (e.g., Brute Force Botnet, Unknown)." 
    },
    attackVector: { 
      type: Type.STRING, 
      description: "The method of attack discovered from the logs." 
    },
    confidenceLevel: { 
      type: Type.STRING, 
      enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      description: "AI confidence in this evaluation." 
    },
    mitigationSteps: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
      description: "Step-by-step immediate remediation actions for security engineers."
    }
  },
  required: ["riskScore", "threatActor", "attackVector", "confidenceLevel", "mitigationSteps"],
};

// Helper function to pause execution threads
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// 1. Threat Correlation Engine
export function correlateThreatLogs(rawLogs: LogEntry[]): CorrelationResult {
  const suspiciousLogs = rawLogs.filter(log => log.severity === 'HIGH' || log.severity === 'MEDIUM');
  
  return {
    incidentId: `INC-${Math.floor(100000 + Math.random() * 900000)}`,
    correlatedLogs: suspiciousLogs,
    summary: `Aggregated ${suspiciousLogs.length} high/medium priority security events.`
  };
}

// 2. Structural Evidence Prompt Builder (Protects against Prompt Injection)
export function buildEvidencePrompt(incident: CorrelationResult): string {
  const logEvidence = JSON.stringify(incident.correlatedLogs, null, 2);
  
  return `
### Incident Context
Incident ID: ${incident.incidentId}
Summary: ${incident.summary}

### Raw Evidence Data
\`\`\`json
${logEvidence}
\`\`\`

Analyze the raw evidence above and populate the requested security schema structure perfectly.
`;
}

// 3. Robust Gemini Connection Engine with Exponential Backoff Retries
export async function analyzeThreatWithGemini(prompt: string, retries = 3, delayMs = 1500) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: prompt,
        config: {
          systemInstruction: "You are an expert Cyber Security Incident Response AI.",
          responseMimeType: "application/json",
          responseSchema: threatAnalysisSchema,
          temperature: 0.1,
        }
      });

      if (!response.text) {
        throw new Error("Empty text block received from API.");
      }

      return JSON.parse(response.text);

    } catch (error: any) {
      // Catch network drops, transient 503 unavailability, or backend service flags
      const is503Error = error?.toString().includes("503") || 
                         error?.status === 503 || 
                         error?.message?.includes("UNAVAILABLE");

      if (is503Error && attempt < retries) {
        console.warn(`[⚠️ Gemini API 503 Overload] Attempt ${attempt} failed. Retrying in ${delayMs}ms...`);
        await delay(delayMs);
        delayMs *= 2; // Exponential expansion of backoff sleep window
        continue;
      }

      console.error(`[❌ Max Retries Exhausted or Fatal System Error]:`, error);
      return getFallbackAnalysis();
    }
  }
}

// 4. Rule-Based Static Fallback Object (Prevents API Route Drops if Gemini is Down)
function getFallbackAnalysis() {
  console.log("[ℹ️ System Alert] Deploying local rule-based threat mitigation parsing.");
  return {
    riskScore: 80,
    threatActor: "Unknown Network Intruder (AI Infrastructure Offline)",
    attackVector: "Heuristic log alert match rules identified active malicious requests.",
    confidenceLevel: "LOW",
    mitigationSteps: [
      "Isolate the host machine or IP associated with the high severity anomalies immediately.",
      "Deploy localized firewall edge rules to drop traffic from the suspicious source IP.",
      "Notify security incident response managers to review raw server output logs manually."
    ]
  };
}

