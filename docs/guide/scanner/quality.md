# Scanner: Code Quality

Maintainability smells, not vulnerabilities: cyclomatic complexity, function length, nesting depth, parameter count, and cross-file duplicate code. Covers Go, Python, JavaScript/TypeScript, PHP, Ruby, and Java.

Off by default — enable with `--scanners quality`.

This is a genuinely different problem shape from the [SAST scanner](sast.md) and is architecturally independent of it — no shared taint-tracking or query infrastructure, just its own small per-language "what counts as a function" node-type sets.

## Rules

| Rule | Severity | Threshold | Detects |
|---|---|---|---|
| `quality-cyclomatic-complexity` | MEDIUM | 10 | McCabe complexity (1 + one per decision point) over threshold |
| `quality-function-length` | LOW | 50 lines | A function/method/lambda/closure spanning more lines than that |
| `quality-nesting-depth` | LOW | 4 | Nested control-flow blocks (if/for/while/switch/try) deeper than that |
| `quality-parameter-count` | LOW | 5 | A function/method taking more parameters than that |
| `quality-duplicate-code` | MEDIUM | 6 significant lines, ≥30 non-whitespace chars | A block of code that also appears elsewhere in the scanned tree |

None of the thresholds are currently configurable — hardcoded, documented here. Configurability (per-project `.ojo.yaml` overrides) is a natural follow-up, not built yet.

## The four AST metrics

For every function/method/lambda/closure found (the same "what counts as a function" boundary — Go's `*ast.FuncDecl`/`*ast.FuncLit`; Python's `function_definition`/`lambda`; JS/TS's `function_declaration`/`function_expression`/`arrow_function`/`method_definition`/generators; PHP's `function_definition`/`method_declaration`/`anonymous_function`/`arrow_function`; Ruby's `method`/`singleton_method`/`lambda`/`block`; Java's `method_declaration`/`constructor_declaration`/`lambda_expression`), ojo computes:

- **Length**: line span of the whole function node.
- **Parameter count**: `NamedChildCount()` of the parameter list — verified directly that tree-sitter's named/anonymous distinction already excludes punctuation (`(`, `,`, `)`) for all five tree-sitter-backed languages, so no per-language parameter-node-type enumeration was needed.
- **Nesting depth**: max depth of nested block-level control constructs (if/for/while/switch/try) — independent of complexity: ten sibling `if`s is high complexity but nesting depth 1; one `if` inside a `for` inside an `if` is depth 3 regardless of how many total branches exist.
- **Cyclomatic complexity**: McCabe's `1 + decision points`, counted per language against a verified node-type table (see "Honest ceiling" below for exactly what counts and what doesn't).

## Duplicate code detection

Deliberately **line-based, not token/AST-based** — a "least effort, still correct" choice specific to this one metric: duplication detection doesn't need language-aware parsing (both PMD's CPD and jscpd support plain lexical modes), and a line-based approach is language-agnostic for free, one algorithm for all six languages instead of six per-language token-stream extractors.

Algorithm: normalize each file to its non-blank, whitespace-trimmed lines (keeping a mapping back to real line numbers); slide a 6-line window across every file, hashing each window; group by hash across the whole scanned tree. A hash with 2+ occurrences is a duplicate — each match is then *extended* forward line-by-line as far as every occurrence keeps matching in lock-step, so what's reported is the actual full duplicate block, not just the minimum 6-line window. Windows below ~30 non-whitespace characters are skipped (filters trivial matches like runs of `}`), and once a block is reported, later overlapping windows in the same file are skipped so one long duplicate doesn't produce a spam of findings.

## Honest ceiling

- **Cyclomatic complexity's decision-point table is the common/core branch constructs, not exhaustive.** Verified directly against each grammar (same discipline as every SAST rule) before writing any code, but scoped to what's common: `if`/`elif`/`for`/`while`/`switch`-`case`/`catch`/ternary/`&&`/`||` and their per-language equivalents. **Not counted**: Python `match` statements (3.10+), JS `for-in`/`for-of`/`do-while`, Java enhanced-`for`, Ruby `unless`/`until`, PHP `match` expressions. Code using these constructs will show a slightly lower complexity than it should — a real, documented gap, not a claim of exhaustive coverage. Add them if they turn out to matter in practice.
- **`&&`/`||` detection requires an operator-field check, not a type-name match**, in JS/PHP/Ruby/Java: all four grammars overload one node type (`binary_expression`/`binary`) for logical operators *and* arithmetic/comparison — `a + b`, `a > b`, and `a && b` all parse to the same node type. Only Python has a dedicated `boolean_operator` node type distinct from comparison/arithmetic, so it needed no such filter.
- **Java's `switch_label` needs a text check, not a type-name match**: unlike JS's distinct `switch_case`/`switch_default` node types, Java's grammar wraps both `case X:` and `default:` in the same `switch_label` node — disambiguated by checking whether the node's text starts with `case`.
- **A Ruby method with an empty body has no body node at all** — `def f(x)\nend` doesn't construct a `body_statement` node the way a non-empty body does. Handled by treating a missing body as zero decision points/nesting rather than crashing; the function's own span is still used for length. Verified directly (an early version of the fixture used to design this caught it).
- **Parameter counting is best-effort for single-argument lambdas without parentheses** (e.g. Ruby's `->(x) { x }` parses fine, but some grammars' single-unparenthesized-parameter forms may not expose the same `parameters` field shape) — low practical impact, since undercounting a 1-parameter lambda to 0 never crosses the 5-parameter threshold anyway.
- **Duplicate detection is textual, not semantic.** Renaming a variable, reordering independent statements, or reformatting breaks the match — this finds copy-paste duplicates, not refactoring opportunities a human reviewer would recognize as "the same logic." That's the deliberate tradeoff for staying language-agnostic and dependency-free; a genuine semantic-clone detector is a different, much larger feature.
- **No GitLab Code Quality report.** `-g/--gitlab` writes four GitLab security report formats (dependency scanning, SAST, secret detection, SBOM) but not GitLab's separate CodeClimate-compatible `gl-code-quality-report.json` format — `quality` findings currently only reach GitLab via the generic JSON/SARIF/table outputs, not a dedicated CI integration. A natural follow-up, not built yet.
