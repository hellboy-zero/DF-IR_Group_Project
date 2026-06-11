import express, { Request, Response } from 'express';
import { 
  correlateThreatLogs, 
  buildEvidencePrompt, 
  analyzeThreatWithGemini, 
  LogEntry 
} from './threatService';

const app = express();
app.use(express.json());

app.post('/api/analyze-threat', async (req: Request, res: Response): Promise<void> => {
  try {
    const rawLogs: LogEntry[] = req.body.logs;

    if (!rawLogs || !Array.isArray(rawLogs)) {
      res.status(400).json({ error: "Invalid request payload. 'logs' field must be an array." });
      return;
    }

    // Step 1: Correlate and isolate threat logs
    const correlationData = correlateThreatLogs(rawLogs);
    
    if (correlationData.correlatedLogs.length === 0) {
      res.status(200).json({ 
        message: "No severe security anomalies detected during initial log correlation.", 
        riskScore: 0 
      });
      return;
    }

    // Step 2: Assemble safe prompt package
    const completedPrompt = buildEvidencePrompt(correlationData);

    // Step 3: Fetch structural analytical result
    const aiAnalysis = await analyzeThreatWithGemini(completedPrompt);

    // Step 4: Outward integrated delivery return
    res.status(200).json({
      incidentId: correlationData.incidentId,
      processedLogsCount: correlationData.correlatedLogs.length,
      analysis: aiAnalysis
    });

  } catch (error: any) {
    res.status(500).json({ error: error.message || "Internal Service Tracking Failure" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server successfully deployed and running on port ${PORT}`);
});

