import ts from 'typescript';
import { describe, expect, it } from 'vitest';

// Every visible string goes through the dictionaries (docs/UI_GUIDELINES.md): this test parses
// the UI sources and fails on text written in a component instead of `t(...)`. It looks at JSX
// text, at the attributes a user sees or hears (title, aria-label, placeholder, alt...) and at the
// text-bearing properties of chart options (axis and series names, titles, graphic text).

// `lib/errorReport.ts` builds the technical bug report of "Copy details": a fixed English format
// meant for the developers, like a stack trace.
const SOURCES = import.meta.glob(
  ['../**/*.{ts,tsx}', '!../**/*.test.{ts,tsx}', '!../api/types/**', '!../i18n/**', '!../test/**', '!../lib/errorReport.ts'],
  {
    query: '?raw',
    import: 'default',
    eager: true,
  },
) as Record<string, string>;

/** JSX attributes whose value is shown or read out. */
const VISIBLE_ATTRIBUTES = new Set([
  'title',
  'aria-label',
  'aria-description',
  'aria-roledescription',
  'aria-valuetext',
  'aria-placeholder',
  'placeholder',
  'alt',
  'label',
]);

/** Object properties carrying visible text in ECharts options (`name` of a series, axis, title). */
const VISIBLE_PROPERTIES = new Set(['text', 'subtext', 'name']);

/**
 * Literal texts that are the same in every language, with the reason. Anything else with a
 * letter in it must come from the dictionaries.
 */
const LANGUAGE_NEUTRAL = new Map<string, string>([
  ['NetSift', 'product name'],
  ['DER', 'certificate encoding name'],
  ['PEM', 'certificate encoding name'],
  ['Raw IP', 'link-layer type name (LINKTYPE_RAW), a technical identifier'],
  ['Linux SLL', 'link-layer type name (LINKTYPE_LINUX_SLL), a technical identifier'],
]);

const HAS_LETTER = /\p{L}/u;

interface Finding {
  file: string;
  line: number;
  text: string;
}

/** String content of a literal expression, or null for anything computed. */
function literalText(node: ts.Node): string | null {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isTemplateExpression(node)) {
    return [node.head.text, ...node.templateSpans.map((s) => s.literal.text)].join(' ');
  }
  if (ts.isParenthesizedExpression(node)) return literalText(node.expression);
  return null;
}

/** Literals reachable from an attribute value: direct, or both arms of a conditional. */
function literalTexts(node: ts.Expression): string[] {
  if (ts.isConditionalExpression(node)) return [...literalTexts(node.whenTrue), ...literalTexts(node.whenFalse)];
  if (ts.isBinaryExpression(node) && (node.operatorToken.kind === ts.SyntaxKind.BarBarToken || node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)) {
    return literalTexts(node.right);
  }
  const text = literalText(node);
  return text === null ? [] : [text];
}

function isVisible(text: string): boolean {
  const trimmed = text.trim();
  return HAS_LETTER.test(trimmed) && !LANGUAGE_NEUTRAL.has(trimmed);
}

/** A capitalized word followed by at least one more word: `No data`, `Show more`. */
const PROSE = /^[A-Z][a-z]+(?:[ ,][a-zA-Z]+)+[.]?$/;

/** Literals under `new Error(...)`, `throw`, `console.*(...)` or an import: never shown as UI text. */
function isDeveloperText(node: ts.Node): boolean {
  for (let p: ts.Node | undefined = node.parent; p !== undefined; p = p.parent) {
    if (ts.isNewExpression(p) || ts.isThrowStatement(p) || ts.isImportDeclaration(p) || ts.isExportDeclaration(p)) return true;
    if (ts.isCallExpression(p) && /^console\./.test(p.expression.getText())) return true;
    if (ts.isBlock(p) || ts.isSourceFile(p)) return false;
  }
  return false;
}

function scan(file: string, source: string): Finding[] {
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const findings: Finding[] = [];
  const report = (node: ts.Node, text: string) => {
    findings.push({ file, line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1, text: text.trim() });
  };
  const visit = (node: ts.Node) => {
    if (ts.isJsxText(node) && isVisible(node.text)) report(node, node.text);
    if (ts.isJsxAttribute(node) && VISIBLE_ATTRIBUTES.has(node.name.getText(sf)) && node.initializer !== undefined) {
      const init = node.initializer;
      const texts = ts.isStringLiteral(init)
        ? [init.text]
        : ts.isJsxExpression(init) && init.expression !== undefined
          ? literalTexts(init.expression)
          : [];
      for (const text of texts) if (isVisible(text)) report(node, text);
    }
    if (
      ts.isPropertyAssignment(node) &&
      VISIBLE_PROPERTIES.has(node.name.getText(sf)) &&
      // `name: 'value'` keys in data items are identifiers, not text: only flag spaced phrases.
      literalTexts(node.initializer).some((text) => isVisible(text) && /\p{L}\s+\p{L}/u.test(text))
    ) {
      report(node, literalTexts(node.initializer).join(' | '));
    }
    // Text drawn by hand in charts or set on the DOM (`textContent = 'Total'`).
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isPropertyAccessExpression(node.left) &&
      ['textContent', 'innerText', 'title', 'ariaLabel'].includes(node.left.name.text)
    ) {
      for (const text of literalTexts(node.right)) if (isVisible(text)) report(node, text);
    }
    // Any other literal that reads as a sentence (`'No data'`, `'Failed to load'`), wherever it
    // is passed: props, state, return values. Developer messages (errors, console) are exempt.
    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && PROSE.test(node.text) && !isDeveloperText(node)) {
      if (!LANGUAGE_NEUTRAL.has(node.text.trim())) report(node, node.text);
    }
    // A colon written in code between a label and a value: French spaces it (`labelled()`).
    const parts = ts.isTemplateExpression(node)
      ? [node.head.text, ...node.templateSpans.map((span) => span.literal.text)]
      : ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)
        ? [node.text]
        : [];
    if (parts.some((part) => /^: |[^\s:]: $/.test(part)) && !isDeveloperText(node)) report(node, 'hard-coded colon: use labelled()');
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

describe('hard-coded UI strings', () => {
  it('scans the UI sources', () => {
    expect(Object.keys(SOURCES).length).toBeGreaterThan(50);
  });

  it('finds no visible text outside the dictionaries', () => {
    const findings = Object.entries(SOURCES).flatMap(([file, source]) => scan(file, source));
    expect(findings.map((f) => `${f.file.replace(/^\.\.\//, 'src/')}:${f.line} ${JSON.stringify(f.text)}`)).toEqual([]);
  });

  it('detects the patterns it is meant to catch', () => {
    const sample = [
      'export const A = () => <p title="Open file">Hello <b>{x}</b></p>;',
      'export const B = () => <input placeholder={cond ? "Search" : t("x")} aria-label={`Close ${n}`} />;',
      'el.textContent = "Total";',
      'const empty = "No data found"; throw new Error("Bad state here");',
      'const line = `${label}: ${value}`;',
    ].join('\n');
    expect(scan('sample.tsx', sample).map((f) => f.text)).toEqual([
      'Open file',
      'Open file',
      'Hello',
      'Search',
      'Close',
      'Total',
      'No data found',
      'hard-coded colon: use labelled()',
    ]);
  });
});
