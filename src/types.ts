export type Severity = "low" | "medium" | "high" | "critical";

export interface Detection {
  /** Rule that triggered the detection. */
  rule: string;
  /** Human-readable description of the finding. */
  message: string;
  /** Severity level. */
  severity: Severity;
  /** The matched text snippet. */
  match: string;
}

export interface ScanResult {
  input: string;
  detections: Detection[];
  passed: boolean;
  maxSeverity: Severity | "none";
}

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

export interface ToolDefinition {
  name: string;
  description: string;
  /** Argument names that are allowed. */
  allowedArguments?: string[];
  /** Argument names that are forbidden. */
  forbiddenArguments?: string[];
  /** If true, the tool requires human approval before execution. */
  requiresApproval?: boolean;
}

export interface ToolScanResult {
  tool: ToolCall;
  allowed: boolean;
  detections: Detection[];
  reason: string;
  requiresApproval: boolean;
}

export interface ShieldRule {
  name: string;
  description: string;
  severity: Severity;
  /** Returns detections if the rule matches. */
  check(input: string): Detection[];
}

export interface ShieldOptions {
  /** Custom rules to add on top of defaults. */
  rules?: ShieldRule[];
  /** Disable default rules. */
  disableDefaults?: boolean;
  /** Severity threshold. Detections below this are ignored. */
  minSeverity?: Severity;
  /** Tool definitions for tool-call safety checks. */
  tools?: ToolDefinition[];
  /** If true, block on any detection. If false, just report. */
  blockOnDetection?: boolean;
}

export interface ShieldResult {
  scan: ScanResult;
  toolScans: ToolScanResult[];
  blocked: boolean;
  reason: string;
}
