# ShieldRail API

## createShield(options?)

Creates a ShieldRail instance.

### Options

- rules: ShieldRule[] - Custom rules on top of defaults.
- disableDefaults: boolean - Disable built-in rules.
- minSeverity: Severity - Filter detections below this level.
- tools: ToolDefinition[] - Tool definitions for tool-call safety.
- blockOnDetection: boolean - Block on any detection. Default true.

## shield.scan(input)

Scans text for prompt injection and risky patterns. Returns ScanResult.

## shield.scanTools(calls)

Scans tool calls against registered definitions. Returns ToolScanResult[].

## shield.guard(input, toolCalls?)

Full guard: scans input and tools, returns ShieldResult with blocked flag.

## shield.addRule(rule)

Add a custom rule at runtime.

## shield.registerTool(tool)

Register a tool definition at runtime.

## Default Rules

- ignore-previous-instructions (high)
- role-manipulation (high)
- instruction-extraction (medium)
- jailbreak-patterns (critical)
- data-exfiltration (high)
- tool-override (high)
- encoding-evasion (medium)

## Tool Safety Checks

- Unknown tool detection
- Allowed/forbidden argument enforcement
- Command injection in argument values
- SQL injection in argument values
- Path traversal in argument values
- XSS patterns in argument values

## Custom Rules

Implement the ShieldRule interface:

```ts
interface ShieldRule {
  name: string;
  description: string;
  severity: Severity;
  check(input: string): Detection[];
}
```
