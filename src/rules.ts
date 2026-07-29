import type { Detection, ShieldRule } from "./types";

const SEVERITY_ORDER = ["low", "medium", "high", "critical"] as const;

export function severityRank(s: string): number {
  return SEVERITY_ORDER.indexOf(s as (typeof SEVERITY_ORDER)[number]);
}

/**
 * Default prompt injection detection rules.
 * These are heuristic pattern-matching rules, not a complete security solution.
 * They catch common injection patterns in user input and retrieved context.
 */
export const DEFAULT_RULES: ShieldRule[] = [
  {
    name: "ignore-previous-instructions",
    description: "Detects attempts to override system instructions",
    severity: "high",
    check(input: string): Detection[] {
      const patterns = [
        /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/gi,
        /disregard\s+(all\s+)?(previous|prior)\s+(instructions?|prompts?)/gi
      ];
      return matchPatterns(input, patterns, this.name, this.severity);
    }
  },
  {
    name: "role-manipulation",
    description: "Detects attempts to change the assistant role",
    severity: "high",
    check(input: string): Detection[] {
      const patterns = [
        /you\s+are\s+now\s+(a|an)\s+/gi,
        /act\s+as\s+(a|an)\s+/gi,
        /pretend\s+(you\s+are|to\s+be)\s+/gi,
        /from\s+now\s+on[,\s]+you\s+/gi
      ];
      return matchPatterns(input, patterns, this.name, this.severity);
    }
  },
  {
    name: "instruction-extraction",
    description: "Detects attempts to extract system instructions",
    severity: "medium",
    check(input: string): Detection[] {
      const patterns = [
        /(reveal|show|print|output|display)\s+(your\s+)?(system\s+)?(instructions?|prompts?|rules?)/gi,
        /what\s+(are|is)\s+your\s+(system\s+)?(instructions?|prompts?)/gi
      ];
      return matchPatterns(input, patterns, this.name, this.severity);
    }
  },
  {
    name: "jailbreak-patterns",
    description: "Detects common jailbreak language",
    severity: "critical",
    check(input: string): Detection[] {
      const patterns = [
        /DAN\s+mode/gi,
        /developer\s+mode/gi,
        /jailbreak/gi,
        /no\s+restrictions/gi,
        /unrestricted\s+mode/gi
      ];
      return matchPatterns(input, patterns, this.name, this.severity);
    }
  },
  {
    name: "data-exfiltration",
    description: "Detects attempts to exfiltrate data",
    severity: "high",
    check(input: string): Detection[] {
      const patterns = [
        /send\s+(this|the)\s+(data|information|content)\s+to/gi,
        /post\s+(this|the)\s+.*\s+to\s+(a|an)?\s*(url|endpoint|webhook|api)/gi,
        /fetch\s+(from|url)\s*[: ]/gi
      ];
      return matchPatterns(input, patterns, this.name, this.severity);
    }
  },
  {
    name: "tool-override",
    description: "Detects attempts to override or bypass tool restrictions",
    severity: "high",
    check(input: string): Detection[] {
      const patterns = [
        /execute\s+(any|all|every)\s+(command|tool|function)/gi,
        /run\s+(any|all)\s+(command|script|code)/gi,
        /bypass\s+(all\s+)?(restrictions|safety|guards)/gi
      ];
      return matchPatterns(input, patterns, this.name, this.severity);
    }
  },
  {
    name: "encoding-evasion",
    description: "Detects common encoding tricks used to evade detection",
    severity: "medium",
    check(input: string): Detection[] {
      const patterns = [
        /\\x[0-9a-f]{2}/gi,
        /\\u[0-9a-f]{4}/gi,
        /base64\s*[: ]/gi,
        /atob\s*\(/gi,
        /decode\s*\(.*base64/gi
      ];
      return matchPatterns(input, patterns, this.name, this.severity);
    }
  }
];

function matchPatterns(
  input: string,
  patterns: RegExp[],
  rule: string,
  severity: Detection["severity"]
): Detection[] {
  const detections: Detection[] = [];
  for (const pattern of patterns) {
    let match: RegExpExecArray | null;
    pattern.lastIndex = 0;
    while ((match = pattern.exec(input)) !== null) {
      detections.push({
        rule,
        message: `Pattern matched: ${match[0]}`,
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
