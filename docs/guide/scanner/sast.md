# Scanner: SAST

Static analysis over Go, Python, JavaScript/TypeScript, PHP, Ruby, and Java source. Go uses the standard library's `go/ast`; the rest use [`gotreesitter`](https://github.com/odvcencio/gotreesitter), a pure-Go tree-sitter runtime. None of it needs cgo.

Off by default — enable with `--scanners sast`.

## Language scope: Go, Python, JS/TS, PHP, Ruby, Java — no cgo

Real multi-language static analysis normally means a proper parser per language (tree-sitter, typically), and the standard Go bindings for that are **cgo-based** — they need a C toolchain at build time, which breaks `GOOS=x GOARCH=y go build` cross-compilation working out of the box. Go source gets the stdlib parser for free, no tradeoff needed.

Python needed a real decision: the obvious pure-Go Python parser, [`gpython`](https://github.com/go-python/gpython), turned out **not to parse f-strings, the walrus operator, or `match` statements** — a syntax error on any of those aborts parsing the whole file, and unparseable files are silently skipped (same policy as Go). Since f-strings alone appear in most real modern Python, that would have meant near-total silent under-coverage — the worst failure mode for a security tool. `gotreesitter` was verified directly (not assumed) against all three constructs before being adopted: it loads the actual grammar tables extracted from upstream `tree-sitter-python`'s C source, reimplementing only the parsing/query engine in Go, not the grammar itself. It's a young project (first commit ~2026-02) — a real tradeoff versus a decade-hardened cgo binding, accepted deliberately for the no-cgo build story.

JS/TS reused `gotreesitter` (its javascript, typescript, and tsx grammars) rather than re-litigating the parser choice, but the same "verify, don't assume" rule applied: modern syntax (optional chaining, template literals, private class fields, decorators, generics, JSX) was tested directly against all three grammars before writing any rules, and all parsed clean. `.tsx` gets its own grammar rather than reusing TypeScript's, since plain TypeScript can't contain JSX — the `jsx_attribute` node type doesn't even exist in that grammar's symbol table (confirmed: compiling a JSX query against it fails with "unknown node type").

PHP reused `gotreesitter`'s php grammar the same way: modern PHP 8 syntax (enums, readonly properties, named arguments, the nullsafe operator, match expressions, attributes, union types, first-class callable syntax, arrow functions, constructor property promotion) was tested directly before writing any rule, all parsed clean.

Ruby reused `gotreesitter`'s ruby grammar the same way: modern Ruby syntax (safe navigation `&.`, pattern matching via `case/in`, endless methods, keyword arguments, hash-shorthand, heredocs, numbered block parameters) was tested directly before writing any rule, all parsed clean.

Java reused `gotreesitter`'s java grammar the same way: modern Java syntax (records, sealed interfaces, switch expressions, text blocks, `var`, try-with-resources, `instanceof` pattern matching) was tested directly before writing any rule, all parsed clean.

Rules are compiled tree-sitter queries (`internal/sast/python.go`, `internal/sast/javascript.go`, `internal/sast/php.go`, `internal/sast/ruby.go`, `internal/sast/java.go`) plus a small Go predicate for checks a query alone can't express (e.g. "is this argument a literal or built dynamically"), curated against [semgrep-rules](https://github.com/semgrep/semgrep-rules)' language-specific rulesets rather than executing semgrep's actual pattern engine.

Other languages are still out of scope — revisit per-language the same way Python, JS/TS, PHP, Ruby, and Java were: check what a candidate parser actually handles before committing.

## Built-in rules — Go (9)

| Rule | Severity | Detects |
|---|---|---|
| `go-hardcoded-secret` | MEDIUM | A literal string assigned to a variable named `password`/`secret`/`apikey`/`token` |
| `go-command-injection` | HIGH | `os/exec.Command`/`CommandContext` with an argument built via `fmt.Sprintf`/string concatenation instead of a literal |
| `go-sql-injection` | HIGH | `database/sql` `Query`/`Exec`/`QueryRow` (and `...Context` variants) with a query string built via `fmt.Sprintf`/concatenation instead of a literal/placeholders |
| `go-weak-hash` | LOW | `crypto/md5` or `crypto/sha1` usage |
| `go-weak-cipher-des` | MEDIUM | `crypto/des` usage |
| `go-insecure-random-for-secrets` | INFO | `math/rand` used inside a function whose name suggests it generates a token/session/key/secret |
| `go-discarded-auth-error` | HIGH | An auth-relevant call (`.Verify(`, `.Authenticate(`, `bcrypt.CompareHashAndPassword`) used as a bare statement, discarding its error return |
| `go-tls-insecure-skip-verify` | HIGH | `tls.Config{InsecureSkipVerify: true}` |
| `go-permissive-file-mode` | MEDIUM | `os.OpenFile`/`os.MkdirAll`/`os.Chmod` called with mode `0777`/`0666` |

## Built-in rules — Python (11)

| Rule | Severity | Detects |
|---|---|---|
| `py-hardcoded-secret` | MEDIUM | A literal string assigned to a variable named `password`/`secret`/`apikey`/`token` |
| `py-eval-exec` | HIGH | `eval(...)` or `exec(...)` called at all |
| `py-command-injection` | HIGH | `os.system(...)`, or `subprocess.{run,call,Popen,check_call,check_output}(..., shell=True)` |
| `py-sql-injection` | HIGH | `.execute(`/`.executemany(` with a query built via f-string interpolation, `%`-formatting, concatenation, or `.format(...)` instead of parameter placeholders |
| `py-weak-hash` | LOW | `hashlib.md5`/`hashlib.sha1` usage |
| `py-pickle-deserialization` | HIGH | `pickle.load`/`pickle.loads` usage |
| `py-yaml-unsafe-load` | MEDIUM | `yaml.load(...)` without `Loader=yaml.SafeLoader`/`CSafeLoader` |
| `py-insecure-random-for-secrets` | INFO | The `random` module used inside a function whose name suggests it generates a token/session/secret |
| `py-tls-verify-disabled` | HIGH | `requests.*(..., verify=False)` or `ssl._create_unverified_context()` |
| `py-flask-debug-enabled` | MEDIUM | `app.run(..., debug=True)` in a file that imports `flask` |
| `py-jinja2-autoescape-disabled` | MEDIUM | `Environment(..., autoescape=False)` in a file that imports `jinja2` |

## Built-in rules — JavaScript / TypeScript / TSX (11)

Applies to `.js`/`.jsx`/`.mjs`/`.cjs` (javascript grammar), `.ts`/`.mts`/`.cts` (typescript grammar), and `.tsx` (tsx grammar). `js-react-dangerously-set-innerhtml` only runs against the js/tsx grammars — plain TypeScript can't contain JSX.

| Rule | Severity | Detects |
|---|---|---|
| `js-hardcoded-secret` | MEDIUM | A literal string assigned to a variable named `password`/`secret`/`apikey`/`token` |
| `js-eval-detected` | HIGH | `eval(...)` or `new Function(...)` called at all |
| `js-command-injection` | HIGH | `child_process.exec`/`execSync` with a command built via template-literal interpolation or `+` concatenation instead of a literal |
| `js-sql-injection` | HIGH | `.query(`/`.execute(` with a query built via template-literal interpolation or `+` concatenation instead of parameterized placeholders |
| `js-weak-hash` | LOW | `crypto.createHash('md5')` or `crypto.createHash('sha1')` |
| `js-insecure-random-for-secrets` | INFO | `Math.random()` used inside a function whose name suggests it generates a token/session/secret |
| `js-tls-verify-disabled` | HIGH | An object literal with `rejectUnauthorized: false` |
| `js-dom-xss-innerhtml` | MEDIUM | `.innerHTML = ...` assigned a non-literal value |
| `js-react-dangerously-set-innerhtml` | MEDIUM | `dangerouslySetInnerHTML` used at all (js/tsx only) |
| `js-open-redirect` | MEDIUM | `res.redirect(...)` with a target built from `req`/`request` or from template-literal interpolation/concatenation |
| `js-jwt-none-algorithm` | HIGH | An object literal with `algorithm: 'none'` |

## Built-in rules — PHP (10)

| Rule | Severity | Detects |
|---|---|---|
| `php-hardcoded-secret` | MEDIUM | A literal string assigned to a variable named `password`/`secret`/`apikey`/`token` |
| `php-eval-detected` | HIGH | `eval(...)` called at all |
| `php-command-injection` | HIGH | `system`/`exec`/`shell_exec`/`passthru`/`popen`/`proc_open` with a command built via `.` concatenation or string interpolation instead of a literal |
| `php-sql-injection` | HIGH | `->query(`/`->exec(` (PDO/mysqli OOP style) with a query built via concatenation/interpolation instead of a prepared-statement placeholder |
| `php-weak-hash` | LOW | `md5()`/`sha1()`, or `hash('md5'/'sha1', ...)` |
| `php-insecure-deserialization` | HIGH | `unserialize(...)` called at all |
| `php-insecure-random-for-secrets` | INFO | `rand()`/`mt_rand()` used inside a function whose name suggests it generates a token/session/secret |
| `php-tls-verify-disabled` | HIGH | An array literal with `'verify_peer'`/`'verify_peer_name' => false`, or `curl_setopt(..., CURLOPT_SSL_VERIFYPEER`/`CURLOPT_SSL_VERIFYHOST, false)` |
| `php-lfi-include` | HIGH | `include`/`include_once`/`require`/`require_once` with a non-literal path |
| `php-preg-replace-eval-modifier` | HIGH | `preg_replace(...)` whose pattern uses the `/e` modifier (evaluates the replacement as PHP code) |

## Built-in rules — Ruby (10)

| Rule | Severity | Detects |
|---|---|---|
| `ruby-hardcoded-secret` | MEDIUM | A literal string assigned to a variable named `password`/`secret`/`apikey`/`token` |
| `ruby-eval-detected` | HIGH | `eval(...)` called at all |
| `ruby-command-injection` | HIGH | `system`/`exec`/`spawn` with a command built via `+` concatenation/interpolation instead of a literal, or a backtick/`%x{}` subshell that interpolates a value |
| `ruby-sql-injection` | HIGH | `where`/`find_by_sql`/`execute`/`select_all`/`select_one`/`exec_query` with a query built via string interpolation or concatenation instead of a bound parameter |
| `ruby-weak-hash` | LOW | `Digest::MD5`/`Digest::SHA1` usage |
| `ruby-insecure-deserialization` | HIGH | `Marshal.load(...)`, or `YAML.load(...)` (as opposed to `YAML.safe_load`) |
| `ruby-insecure-random-for-secrets` | INFO | `Kernel#rand` used inside a method whose name suggests it generates a token/session/secret |
| `ruby-tls-verify-disabled` | HIGH | `OpenSSL::SSL::VERIFY_NONE` used anywhere |
| `ruby-mass-assignment` | MEDIUM | `params.permit!` (bypasses Rails strong parameters entirely) |
| `ruby-open-redirect` | MEDIUM | `redirect_to(...)` with a target built from `params`/`request` or from string interpolation/concatenation |

## Built-in rules — Java (9)

| Rule | Severity | Detects |
|---|---|---|
| `java-hardcoded-secret` | MEDIUM | A literal string assigned to a variable named `password`/`secret`/`apikey`/`token` |
| `java-command-injection` | HIGH | `Runtime.getRuntime().exec(...)` or `new ProcessBuilder(...)` with a command built via `+` concatenation instead of a literal/argument array |
| `java-sql-injection` | HIGH | `Statement`'s `execute`/`executeQuery`/`executeUpdate` with a query built via `+` concatenation instead of a `PreparedStatement` placeholder |
| `java-weak-hash` | LOW | `MessageDigest.getInstance("MD5"/"SHA1"/"SHA-1")` |
| `java-weak-cipher` | MEDIUM | `Cipher.getInstance(...)` where the algorithm string contains `DES`, `RC4`, or `ECB` |
| `java-insecure-deserialization` | HIGH | `.readObject()` called at all (`ObjectInputStream`) |
| `java-insecure-random-for-secrets` | INFO | `new Random()` used inside a method whose name suggests it generates a token/session/secret |
| `java-tls-trust-manager-bypass` | HIGH | A custom `X509TrustManager`/`HostnameVerifier` implementation |
| `java-xxe` | HIGH | `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory` `.newInstance()` called at all (vulnerable to XXE unless explicitly hardened) |

## Honest ceiling

This is a curated, query-based linter, not a Semgrep replacement — yet. Specifically it has:

- **No taint tracking.** Rules flag syntactic *candidates* (e.g. "this SQL query is built with an f-string"); they can't trace whether the interpolated value actually originates from untrusted input. Expect a real false-positive rate that needs human triage.
- **No interprocedural analysis.** Each function body is analyzed alone; there's no call graph.
- **No general metavariable pattern language.** Python, JS/TS, PHP, Ruby, and Java rules are individually-compiled tree-sitter queries (closer to Semgrep's own matching primitive than Go's hand-rolled `ast.Inspect` walks are, but each is still a fixed query plus bespoke Go filtering, not a shared pattern DSL a user can extend). Go rules remain bespoke `go/ast` predicates.
- **Parser ceiling:** whatever `gotreesitter`'s grammars don't parse gets silently skipped, same policy as Go. Verified against a real, hand-picked set of modern-syntax constructs per language at adoption time (f-strings/walrus/match for Python; optional chaining/decorators/generics/JSX for JS/TS; enums/readonly/named-args/nullsafe/match/attributes/union-types/first-class-callables/arrow-fns/constructor-promotion for PHP; safe-navigation/pattern-matching/endless-methods/keyword-args/heredocs for Ruby; records/sealed-interfaces/switch-expressions/text-blocks/var/try-with-resources/instanceof-patterns for Java); not exhaustively fuzzed against the full modern grammar of any of them.
- **`js-command-injection`/`js-open-redirect`/`ruby-open-redirect` name-match only:** `child_process`/`cp`, `req`/`request`, and `params` are matched by identifier name, not import/framework resolution — an unusually-named alias won't be caught, and (unlike Python's `fileImports` check used for the Flask/Jinja2 rules) there's no equivalent import-verification step here yet.
- **`php-sql-injection` covers OOP-style calls only:** `->query(`/`->exec(` (PDO/mysqli object usage). Procedural `mysqli_query()`/`mysql_query()`/`pg_query()` aren't covered — each has a different argument signature (connection first, query in a different position), and the OOP form is the dominant modern idiom; add the procedural forms if they turn out to matter in practice.
- **`ruby-sql-injection` matches ActiveRecord/Sequel-style method names only:** `where`/`find_by_sql`/`execute`/etc. by identifier, not by verifying the receiver is actually an ActiveRecord model or DB connection — a user-defined method with the same name would false-positive.
- **`java-sql-injection`/`java-command-injection` match method/type names only:** `executeQuery`/`Runtime`/`ProcessBuilder` etc. by identifier, not by verifying the receiver's declared type is actually `java.sql.Statement` — a user-defined class with a method of the same name would false-positive. `java-tls-trust-manager-bypass` and `java-xxe` deliberately flag unconditionally (any custom TrustManager, any factory creation) rather than trying to detect whether hardening was applied elsewhere — same "flag the candidate, let a human confirm" tradeoff as `php-insecure-deserialization`/`py-pickle-deserialization`.

Rules that overlap with the [secret scanner](secret.md) (`go-hardcoded-secret`, `py-hardcoded-secret`, `js-hardcoded-secret`, `php-hardcoded-secret`, `ruby-hardcoded-secret`, `java-hardcoded-secret`) are intentional, not redundant: the secret scanner does line-level regex over raw text; these rules work on the actual parse tree, catching multi-line/formatted literals the regex misses and correctly ignoring matches inside comments or non-assignment string literals.
