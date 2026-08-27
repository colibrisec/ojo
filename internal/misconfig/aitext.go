package misconfig

import (
	"fmt"
	"regexp"
)

// Shared text heuristics for content an LLM agent reads as instructions or
// tool metadata -- an MCP server's description, a skill's body. Deliberately
// narrow, concrete signals (a specific phrase list, specific codepoints),
// not an attempt at a semantic classifier. Expect a higher false-positive
// rate here than the rest of this package's structural checks; see
// docs/guide/scanner/misconfiguration.md's ceiling notes.

// injectionPhraseRe matches a small set of known prompt-injection/tool-
// poisoning phrasings: instructions telling the model to override its prior
// instructions, or to hide its actions from the user. Both are the
// recurring core of real-world MCP "tool poisoning" and skill/prompt
// injection payloads -- an attacker doesn't need many distinct phrasings to
// achieve either goal, so this list stays short and high-signal rather than
// trying to be exhaustive.
var injectionPhraseRe = regexp.MustCompile(`(?i)(ignore (all |any )?(previous|prior|the above) instructions` +
	`|disregard (the |all )?(above|previous) instructions` +
	`|new instructions\s*:` +
	`|do not (tell|inform|mention (this|it) to) the user` +
	`|without (telling|notifying|the knowledge of) the user` +
	`|hidden from the user` +
	`|reveal your (system prompt|system instructions)` +
	`|this is (a |the )?system (prompt|message|instruction))`)

func hasInjectionLanguage(s string) bool {
	return injectionPhraseRe.MatchString(s)
}

// findHiddenUnicode checks a set of codepoints with real history as an
// invisible payload carrier and no legitimate purpose in ordinary prose:
// the Unicode "tag" block (smuggles invisible instructions past a human
// reviewer while an LLM still decodes them), zero-width space and word
// joiner, the classic bidi override controls (the "Trojan Source"
// mechanism), and a mid-text ZWNBSP. Deliberately excluded: zero-width
// joiner (legitimate in emoji sequences) and the bidi *isolate* characters
// (legitimate in modern i18n text) -- both would cost real false positives
// for a marginal detection gain.
func findHiddenUnicode(s string) (rune, bool) {
	for i, r := range s {
		switch {
		case r >= 0xE0000 && r <= 0xE007F: // Unicode tag block
			return r, true
		case r == 0x200B, r == 0x2060: // zero-width space, word joiner
			return r, true
		case r >= 0x202A && r <= 0x202E: // bidi embedding/override controls
			return r, true
		case r == 0xFEFF && i > 0: // ZWNBSP mid-text -- a leading BOM is normal
			return r, true
		}
	}
	return 0, false
}

func unicodeCodepoint(r rune) string {
	return fmt.Sprintf("%04X", r)
}
