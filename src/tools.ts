import type { Detection, ToolCall, ToolDefinition, ToolScanResult } from "./types";

/**
 * Scans a tool call against its definition for safety.
 * Checks for unknown arguments, forbidden arguments, and suspicious values.
 */
export function scanToolCall(
  call: ToolCall,
  definition: ToolDefinition | undefined
): ToolScanResult {
  const detections: Detection[] = [];
  let allowed = true;
  let reason = "allowed";
  const requiresApproval = definition?.requiresApproval ?? false;

  if (!definition) {
    return {
      tool: call,
      allowed: false,
      detections: [],
      reason: `Unknown tool: ${call.name}`,
      requiresApproval: false
    };
  }

  // Check for unknown arguments
  if (definition.allowedArguments && definition.allowedArguments.length > 0) {
    const allowedSet = new Set(definition.allowedArguments);
    for (const key of Object.keys(call.arguments)) {
      if (!allowedSet.has(key)) {
        detections.push({
          rule: "unknown-argument",
          message: `Argument '${key}' is not in the allowed list for tool '${call.name}'`,
          severity: "high",
          match: key
        });
        allowed = false;
        reason = `Disallowed argument: ${key}`;
      }
    }
  }

  // Check for forbidden arguments
  if (definition.forbiddenArguments) {
    for (const key of Object.keys(call.arguments)) {
      if (definition.forbiddenArguments.includes(key)) {
        detections.push({
          rule: "forbidden-argument",
          message: `Argument '${key}' is forbidden for tool '${call.name}'`,
          severity: "critical",
          match: key
        });
        allowed = false;
        reason = `Forbidden argument: ${key}`;
      }
    }
  }

  // Check argument values for injection patterns
  for (const [key, value] of Object.entries(call.arguments)) {
    if (typeof value === "string") {
 const injectionDetections = scanValueForInjection(value, call.name, key);
      detections.push(...injectionDetections);
      if (injectionDetections.some((d) => d.severity === "critical" || d.severity === "high")) {
        allowed = false;
        reason = `Suspicious value in argument: ${key}`;
      }
    }
  }

  return {
    tool: call,
    allowed,
    detections,
    reason,
    requiresApproval
  };
}

function scanValueForInjection(value: string, toolName: string, argName: string): Detection[] {
  const detections: Detection[] = [];
  const suspiciousPatterns = [
    { pattern: /;.*rm\s+-rf/gi, severity: "critical" as const, rule: "command-injection" },
    { pattern: /\$\(.*\)/g, severity: "high" as const, rule: "command-substitution" },
    { pattern: /\|\s*(sh|bash|zsh|python|ruby|perl)\b/gi, severity: "high" as const, rule: "pipe-to-shell" },
    { pattern: /rm\s+-rf\s+\//gi, severity: "critical" as const, rule: "destructive-command" },
    { pattern: /DROP\s+TABLE/gi, severity: "critical" as const, rule: "sql-injection" },
    { pattern: /UNION\s+SELECT/gi, severity: "high" as const, rule: "sql-injection" },
    { pattern: /<script[^>]*>/gi, severity: "high" as const, rule: "xss" },
    { pattern: /javascript:/gi, severity: "medium" as const, rule: "xss" },
    { pattern: /\.\.\//g, severity: "medium" as const, rule: "path-traversal" },
    { pattern: /\.\.\\/g, severity: "medium" as const, rule: "path-traversal" }
  ];

  for (const { pattern, severity, rule } of suspiciousPatterns) {
    let match: RegExpExecArray | null;
    pattern.lastIndex = 0;
    while ((match = pattern.exec(value)) !== null) {
      detections.push({
        rule,
        message: `Suspicious pattern in ${toolName}.${argName}: ${match[0]}`,
        severity,
        match: match[0]
      });
      if (match.index === pattern.lastIndex) {
        pattern.lastIndex++;
      }
    }
  }

  return detections;
}
