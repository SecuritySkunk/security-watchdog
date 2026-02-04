/**
 * ═══════════════════════════════════════════════════════════════════════════
 * Thermidor Orchestrator - AI-Assisted Implementation Workflow
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * This module provides Thermidor (the coordinating agent) with tools to:
 * 1. Call LM Studio for code generation
 * 2. Validate generated code (TypeScript compilation, ESLint)
 * 3. Run tests against generated code
 * 4. Manage the chunk-by-chunk implementation workflow
 * 
 * Usage:
 *   npx tsx orchestrator.ts generate --module scanner --chunk presidio-stage
 *   npx tsx orchestrator.ts validate src/scanner/pipeline.ts
 *   npx tsx orchestrator.ts test src/scanner/__tests__/pipeline.test.ts
 */

import { execSync, spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

interface OrchestratorConfig {
  lmStudioUrl: string;
  defaultModel: string;
  reasoningModel: string;
  fastModel: string;
  temperature: number;
  maxTokens: number;
  maxRetries: number;
  projectRoot: string;
}

const DEFAULT_CONFIG: OrchestratorConfig = {
  lmStudioUrl: process.env.LM_STUDIO_URL || 'http://10.0.0.229:1234',
  defaultModel: 'qwen2.5-coder-32b-instruct',
  reasoningModel: 'qwq-32b',
  fastModel: 'devstral-small-2507',
  temperature: 0.2,
  maxTokens: 8192,
  maxRetries: 3,
  projectRoot: process.cwd(),
};

// ═══════════════════════════════════════════════════════════════════════════
// LM STUDIO CLIENT
// ═══════════════════════════════════════════════════════════════════════════

interface Message {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface GenerationOptions {
  model?: string;
  temperature?: number;
  maxTokens?: number;
  stop?: string[];
}

interface GenerationResult {
  content: string;
  tokensUsed: number;
  durationMs: number;
  model: string;
}

async function callLMStudio(
  messages: Message[],
  options: GenerationOptions = {},
  config: OrchestratorConfig = DEFAULT_CONFIG
): Promise<GenerationResult> {
  const model = options.model || config.defaultModel;
  const startTime = Date.now();

  const requestBody = {
    model,
    messages,
    temperature: options.temperature ?? config.temperature,
    max_tokens: options.maxTokens ?? config.maxTokens,
    stop: options.stop || ['```', '---'],
    stream: false,
  };

  const response = await fetch(`${config.lmStudioUrl}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`LM Studio API error: ${response.status} - ${error}`);
  }

  const data = await response.json();
  const durationMs = Date.now() - startTime;

  return {
    content: data.choices[0].message.content,
    tokensUsed: data.usage?.total_tokens || 0,
    durationMs,
    model,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// SYSTEM PROMPTS
// ═══════════════════════════════════════════════════════════════════════════

const SYSTEM_PROMPTS = {
  codeGeneration: `You are an expert TypeScript developer implementing the OpenClaw Security Watchdog.

CRITICAL REQUIREMENTS:
- TypeScript strict mode: no 'any' types, explicit return types on all functions
- Follow existing interfaces exactly (types.ts is the source of truth)
- Use established libraries: better-sqlite3, fuse.js, pino for logging
- Implement defensive programming: validate inputs, handle edge cases
- Include JSDoc comments on all public methods
- Use async/await for all I/O operations

OUTPUT FORMAT:
- Output ONLY the TypeScript code, no explanations before or after
- Include all necessary imports at the top
- Use the exact function signatures from the stub
- Mark any assumptions with // ASSUMPTION: comments`,

  errorCorrection: `You are an expert TypeScript developer fixing code for the OpenClaw Security Watchdog.

REQUIREMENTS:
- Fix ONLY the specific error indicated
- Preserve all working functionality
- Maintain TypeScript strict mode compliance
- Output the complete corrected code (not just the fix)`,

  codeReview: `You are a senior security engineer reviewing code for the OpenClaw Security Watchdog.

FOCUS AREAS:
1. Security vulnerabilities (injection, bypass, data leakage)
2. Runtime errors under edge conditions
3. Violations of the fail-closed principle
4. Type safety issues
5. Error handling gaps

OUTPUT FORMAT:
- List issues as numbered items with severity (CRITICAL/HIGH/MEDIUM/LOW)
- Include file:line references where applicable
- Or state "No issues found" if the code is clean`,
};

// ═══════════════════════════════════════════════════════════════════════════
// CODE GENERATION
// ═══════════════════════════════════════════════════════════════════════════

interface GenerateCodeOptions {
  specExcerpt: string;
  interfaces: string;
  existingCode?: string;
  stubSection: string;
  taskDescription: string;
}

async function generateCode(
  options: GenerateCodeOptions,
  config: OrchestratorConfig = DEFAULT_CONFIG
): Promise<GenerationResult> {
  const userPrompt = `## CONTEXT FROM SPECIFICATION
${options.specExcerpt}

## INTERFACES (from types.ts)
${options.interfaces}

${options.existingCode ? `## EXISTING CODE\n${options.existingCode}\n` : ''}

## STUB TO IMPLEMENT
${options.stubSection}

## TASK
${options.taskDescription}

Output only the complete TypeScript code for this chunk.`;

  return callLMStudio(
    [
      { role: 'system', content: SYSTEM_PROMPTS.codeGeneration },
      { role: 'user', content: userPrompt },
    ],
    {},
    config
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// ERROR CORRECTION
// ═══════════════════════════════════════════════════════════════════════════

interface FixErrorOptions {
  code: string;
  errorMessage: string;
  errorType: 'compilation' | 'lint' | 'test' | 'runtime';
}

async function fixError(
  options: FixErrorOptions,
  config: OrchestratorConfig = DEFAULT_CONFIG,
  useReasoningModel: boolean = false
): Promise<GenerationResult> {
  const userPrompt = `## ORIGINAL CODE
\`\`\`typescript
${options.code}
\`\`\`

## ${options.errorType.toUpperCase()} ERROR
${options.errorMessage}

## TASK
Fix the above error while maintaining all other functionality.
Output the complete corrected code (not just the fix).`;

  return callLMStudio(
    [
      { role: 'system', content: SYSTEM_PROMPTS.errorCorrection },
      { role: 'user', content: userPrompt },
    ],
    { model: useReasoningModel ? config.reasoningModel : config.defaultModel },
    config
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

interface ValidationResult {
  success: boolean;
  errors: string[];
  warnings: string[];
}

function runTypeCheck(filePath: string): ValidationResult {
  try {
    execSync(`npx tsc --noEmit --strict ${filePath}`, {
      encoding: 'utf-8',
      stdio: 'pipe',
    });
    return { success: true, errors: [], warnings: [] };
  } catch (error: any) {
    const output = error.stdout || error.stderr || error.message;
    return {
      success: false,
      errors: output.split('\n').filter((l: string) => l.includes('error TS')),
      warnings: output.split('\n').filter((l: string) => l.includes('warning')),
    };
  }
}

function runESLint(filePath: string): ValidationResult {
  try {
    execSync(`npx eslint ${filePath} --max-warnings 0`, {
      encoding: 'utf-8',
      stdio: 'pipe',
    });
    return { success: true, errors: [], warnings: [] };
  } catch (error: any) {
    const output = error.stdout || error.stderr || error.message;
    const lines = output.split('\n');
    return {
      success: false,
      errors: lines.filter((l: string) => l.includes('error')),
      warnings: lines.filter((l: string) => l.includes('warning')),
    };
  }
}

function runTests(testPattern: string): ValidationResult {
  try {
    execSync(`npx vitest run ${testPattern} --reporter=json`, {
      encoding: 'utf-8',
      stdio: 'pipe',
    });
    return { success: true, errors: [], warnings: [] };
  } catch (error: any) {
    const output = error.stdout || error.stderr || error.message;
    return {
      success: false,
      errors: [output],
      warnings: [],
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CODE REVIEW (SECOND PASS)
// ═══════════════════════════════════════════════════════════════════════════

interface ReviewResult {
  issues: Array<{
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    description: string;
    location?: string;
  }>;
  clean: boolean;
}

async function reviewCode(
  code: string,
  config: OrchestratorConfig = DEFAULT_CONFIG
): Promise<ReviewResult> {
  const userPrompt = `Review this code for security issues, logic errors, and edge cases:

\`\`\`typescript
${code}
\`\`\`

Identify any issues that could cause:
1. Security vulnerabilities (injection, bypass, data leakage)
2. Runtime errors under edge conditions
3. Violations of the fail-closed principle

Output a numbered list of issues with severity, or "No issues found" if clean.`;

  const result = await callLMStudio(
    [
      { role: 'system', content: SYSTEM_PROMPTS.codeReview },
      { role: 'user', content: userPrompt },
    ],
    { model: config.reasoningModel },
    config
  );

  // Parse the review output
  if (result.content.toLowerCase().includes('no issues found')) {
    return { issues: [], clean: true };
  }

  // Extract issues from numbered list (simplified parser)
  const issues: ReviewResult['issues'] = [];
  const lines = result.content.split('\n');
  for (const line of lines) {
    const match = line.match(/(\d+)\.\s*(CRITICAL|HIGH|MEDIUM|LOW)[:\s-]+(.+)/i);
    if (match) {
      issues.push({
        severity: match[2].toUpperCase() as any,
        description: match[3].trim(),
      });
    }
  }

  return { issues, clean: issues.length === 0 };
}

// ═══════════════════════════════════════════════════════════════════════════
// ORCHESTRATION WORKFLOW
// ═══════════════════════════════════════════════════════════════════════════

interface ChunkImplementationOptions {
  moduleName: string;
  chunkName: string;
  specPath: string;
  interfacesPath: string;
  stubPath: string;
  outputPath: string;
  testPath?: string;
}

interface ChunkResult {
  success: boolean;
  code: string;
  attempts: number;
  validationPassed: boolean;
  reviewPassed: boolean;
  errors: string[];
}

async function implementChunk(
  options: ChunkImplementationOptions,
  config: OrchestratorConfig = DEFAULT_CONFIG
): Promise<ChunkResult> {
  const result: ChunkResult = {
    success: false,
    code: '',
    attempts: 0,
    validationPassed: false,
    reviewPassed: false,
    errors: [],
  };

  // Load context files
  const specExcerpt = fs.readFileSync(options.specPath, 'utf-8');
  const interfaces = fs.readFileSync(options.interfacesPath, 'utf-8');
  const stubSection = fs.readFileSync(options.stubPath, 'utf-8');

  console.log(`\n═══ Implementing ${options.moduleName}/${options.chunkName} ═══\n`);

  for (let attempt = 1; attempt <= config.maxRetries; attempt++) {
    result.attempts = attempt;
    console.log(`Attempt ${attempt}/${config.maxRetries}...`);

    try {
      // Generate code
      const generation = await generateCode({
        specExcerpt,
        interfaces,
        stubSection,
        taskDescription: `Implement the ${options.chunkName} chunk. Replace all TODO markers with working code.`,
      }, config);

      result.code = generation.content;
      console.log(`  Generated ${generation.tokensUsed} tokens in ${generation.durationMs}ms`);

      // Write to file for validation
      fs.writeFileSync(options.outputPath, result.code);

      // Validate: TypeScript compilation
      console.log('  Checking TypeScript compilation...');
      const typeCheck = runTypeCheck(options.outputPath);
      if (!typeCheck.success) {
        console.log(`  ✗ Compilation failed: ${typeCheck.errors.length} errors`);
        result.errors = typeCheck.errors;

        // Attempt to fix
        const fix = await fixError({
          code: result.code,
          errorMessage: typeCheck.errors.join('\n'),
          errorType: 'compilation',
        }, config);
        result.code = fix.content;
        fs.writeFileSync(options.outputPath, result.code);
        continue;
      }
      console.log('  ✓ TypeScript compilation passed');

      // Validate: ESLint
      console.log('  Checking ESLint...');
      const lintCheck = runESLint(options.outputPath);
      if (!lintCheck.success) {
        console.log(`  ✗ Lint failed: ${lintCheck.errors.length} errors`);
        result.errors = lintCheck.errors;

        const fix = await fixError({
          code: result.code,
          errorMessage: lintCheck.errors.join('\n'),
          errorType: 'lint',
        }, config);
        result.code = fix.content;
        fs.writeFileSync(options.outputPath, result.code);
        continue;
      }
      console.log('  ✓ ESLint passed');

      result.validationPassed = true;

      // Run tests if provided
      if (options.testPath && fs.existsSync(options.testPath)) {
        console.log('  Running tests...');
        const testResult = runTests(options.testPath);
        if (!testResult.success) {
          console.log('  ✗ Tests failed');
          result.errors = testResult.errors;

          const fix = await fixError({
            code: result.code,
            errorMessage: testResult.errors.join('\n'),
            errorType: 'test',
          }, config);
          result.code = fix.content;
          fs.writeFileSync(options.outputPath, result.code);
          continue;
        }
        console.log('  ✓ Tests passed');
      }

      // Security review
      console.log('  Running security review...');
      const review = await reviewCode(result.code, config);
      if (!review.clean) {
        const criticalIssues = review.issues.filter(i => i.severity === 'CRITICAL');
        if (criticalIssues.length > 0) {
          console.log(`  ⚠ Found ${criticalIssues.length} critical issues`);
          result.errors = criticalIssues.map(i => i.description);

          const fix = await fixError({
            code: result.code,
            errorMessage: criticalIssues.map(i => `${i.severity}: ${i.description}`).join('\n'),
            errorType: 'runtime',
          }, config, true); // Use reasoning model for security fixes
          result.code = fix.content;
          fs.writeFileSync(options.outputPath, result.code);
          continue;
        }
        console.log(`  ⚠ Found ${review.issues.length} non-critical issues (acceptable)`);
      } else {
        console.log('  ✓ Security review passed');
      }
      result.reviewPassed = true;

      // Success!
      result.success = true;
      console.log(`\n✓ Successfully implemented ${options.chunkName} in ${attempt} attempt(s)\n`);
      break;

    } catch (error: any) {
      console.log(`  ✗ Error: ${error.message}`);
      result.errors.push(error.message);
    }
  }

  if (!result.success) {
    console.log(`\n✗ Failed to implement ${options.chunkName} after ${config.maxRetries} attempts`);
    console.log('Escalating to human review.\n');
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// CLI INTERFACE
// ═══════════════════════════════════════════════════════════════════════════

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  switch (command) {
    case 'check-server':
      try {
        const response = await fetch(`${DEFAULT_CONFIG.lmStudioUrl}/v1/models`);
        const data = await response.json();
        console.log('✓ LM Studio server is running');
        console.log('Available models:');
        for (const model of data.data || []) {
          console.log(`  - ${model.id}`);
        }
      } catch (error) {
        console.error('✗ Cannot connect to LM Studio');
        process.exit(1);
      }
      break;

    case 'generate':
      console.log('Use implementChunk() function programmatically');
      console.log('See documentation in the playbook.');
      break;

    case 'validate':
      const filePath = args[1];
      if (!filePath) {
        console.error('Usage: validate <file-path>');
        process.exit(1);
      }
      const typeResult = runTypeCheck(filePath);
      const lintResult = runESLint(filePath);
      console.log(`TypeScript: ${typeResult.success ? '✓' : '✗'}`);
      console.log(`ESLint: ${lintResult.success ? '✓' : '✗'}`);
      if (!typeResult.success) typeResult.errors.forEach(e => console.log(`  ${e}`));
      if (!lintResult.success) lintResult.errors.forEach(e => console.log(`  ${e}`));
      break;

    default:
      console.log(`
Thermidor Orchestrator - AI-Assisted Implementation

Commands:
  check-server    - Verify LM Studio connection
  validate <file> - Run TypeScript and ESLint checks
  
For code generation, import this module and use:
  - generateCode() - Generate code from spec/stub
  - fixError()     - Fix compilation/test errors
  - reviewCode()   - Security review with reasoning model
  - implementChunk() - Full chunk workflow with retries

Environment Variables:
  LM_STUDIO_URL   - LM Studio server (default: http://10.0.0.229:1234)
`);
  }
}

main().catch(console.error);

// Export for programmatic use
export {
  callLMStudio,
  generateCode,
  fixError,
  reviewCode,
  implementChunk,
  runTypeCheck,
  runESLint,
  runTests,
  DEFAULT_CONFIG,
  SYSTEM_PROMPTS,
};
export type {
  OrchestratorConfig,
  GenerateCodeOptions,
  FixErrorOptions,
  ChunkImplementationOptions,
  ChunkResult,
  GenerationResult,
  ValidationResult,
  ReviewResult,
};
