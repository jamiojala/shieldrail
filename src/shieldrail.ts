import { DEFAULT_RULES, severityRank } from "./rules";
import { scanToolCall } from "./tools";
import type {
  Detection,
  ScanResult,
  Severity,
  ShieldOptions,
  ShieldResult,
  ShieldRule,
  ToolCall,
  ToolScanResult
} from "./types";

const SEVERITY_RANK: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3
};

/**
 * ShieldRail is a guardrail layer for detecting prompt injection,
 * risky context, and unsafe tool execution paths.
 */
export class ShieldRail {
  private readonly rules: ShieldRule[];
  private readonly minSeverity: Severity;
  private readonly tools: Map<string, import("./types").ToolDefinition>;
  private readonly blockOnDetection: boolean;

  constructor(options: ShieldOptions = {}) {
    const customRules = options.rules ?? [];
    const defaults = options.disableDefaults ? [] : DEFAULT_RULES;
    this.rules = [...defaults, ...customRules];
    this.minSeverity = options.minSeverity ?? "low";
    this.tools = new Map(
      (options.tools ?? []).map((t) => [t.name, t])
    );
    this.blockOnDetection = options.blockOnDetection ?? true;
  }

  /**
   * Scans text input for prompt injection and risky patterns.
   */
  scan(input: string): ScanResult {
    const allDetections: Detection[] = [];

    for (const rule of this.rules) {
      const detections = rule.check(input);
      for (const d of detections) {
        if (SEVERITY_RANK[d.severity] >= SEVERITY_RANK[this.minSeverity]) {
          allDetections.push(d);
        }
      }
    }

    const maxSeverity = getMaxSeverity(allDetections);

    return {
      input,
      detections: allDetections,
      passed: allDetections.length === 0,
      maxSeverity
    };
  }

  /**
   * Scans tool calls against registered tool definitions.
   */
  scanTools(calls: ToolCall[]): ToolScanResult[] {
    return calls.map((call) => {
      const def = this.tools.get(call.name);
      return scanToolCall(call, def);
    });
  }

  /**
   * Full guard: scans input text and tool calls, returns combined result.
   */
  guard(input: string, toolCalls: ToolCall[] = []): ShieldResult {
    const scan = this.scan(input);
    const toolScans = this.scanTools(toolCalls);

    let blocked = false;
    let reason = "passed";

    if (this.blockOnDetection && !scan.passed) {
      blocked = true;
      const topDetection = scan.detections[0];
      reason = topDetection ? `Input blocked: ${topDetection.rule}` : "Input blocked";
    }

    for (const ts of toolScans) {
      if (!ts.allowed) {
        blocked = true;
        reason = `Tool blocked: ${ts.reason}`;
        break;
      }
    }

    return {
      scan,
      toolScans,
      blocked,
      reason
    };
  }

  /**
   * Adds a custom rule at runtime.
   */
  addRule(rule: ShieldRule): void {
    this.rules.push(rule);
  }

  /**
   * Registers a tool definition.
   */
  registerTool(tool: import("./types").ToolDefinition): void {
    this.tools.set(tool.name, tool);
  }
}

function getMaxSeverity(detections: Detection[]): Severity | "none" {
  if (detections.length === 0) return "none";
  let max: Severity = "low";
  for (const d of detections) {
    if (SEVERITY_RANK[d.severity] > SEVERITY_RANK[max]) {
      max = d.severity;
    }
  }
  return max;
}

/** Convenience factory. */
export function createShield(options?: ShieldOptions): ShieldRail {
  return new ShieldRail(options);
}

export { severityRank };
