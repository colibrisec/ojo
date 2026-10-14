package version

import "strings"

// Maven orders versions the way Maven's ComparableVersion does.
func Maven(a, b string) int {
	return parseMaven(a).compare(parseMaven(b))
}

type mavenKind int

const (
	mavenInt mavenKind = iota
	mavenString
	mavenList
)

type mavenItem struct {
	kind  mavenKind
	value string
	items []*mavenItem
}

var mavenQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

var mavenAliases = map[string]string{"ga": "", "final": "", "release": "", "cr": "rc"}

func mavenQualifierKey(q string) string {
	for i, k := range mavenQualifiers {
		if k == q {
			return string(rune('0' + i))
		}
	}
	return string(rune('0'+len(mavenQualifiers))) + "-" + q
}

func newMavenString(s string, followedByDigit bool) *mavenItem {
	if followedByDigit && len(s) == 1 {
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	if alias, ok := mavenAliases[s]; ok {
		s = alias
	}
	return &mavenItem{kind: mavenString, value: s}
}

func newMavenNumberOrString(s string, isDigit bool, followedByDigit bool) *mavenItem {
	if isDigit {
		return &mavenItem{kind: mavenInt, value: strings.TrimLeft(s, "0")}
	}
	return newMavenString(s, followedByDigit)
}

func (it *mavenItem) isNull() bool {
	switch it.kind {
	case mavenInt:
		return it.value == ""
	case mavenString:
		return it.value == ""
	default:
		return len(it.items) == 0
	}
}

func (it *mavenItem) normalize() {
	for i := len(it.items) - 1; i >= 0; i-- {
		last := it.items[i]
		if last.isNull() {
			it.items = append(it.items[:i], it.items[i+1:]...)
		} else if last.kind != mavenList {
			break
		}
	}
}

func parseMaven(v string) *mavenItem {
	v = strings.ToLower(v)
	root := &mavenItem{kind: mavenList}
	list := root
	stack := []*mavenItem{list}
	isDigitRun := false
	start := 0

	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.':
			if i == start {
				list.items = append(list.items, &mavenItem{kind: mavenInt})
			} else {
				list.items = append(list.items, newMavenNumberOrString(v[start:i], isDigitRun, false))
			}
			start = i + 1
		case c == '-':
			if i == start {
				list.items = append(list.items, &mavenItem{kind: mavenInt})
			} else {
				list.items = append(list.items, newMavenNumberOrString(v[start:i], isDigitRun, false))
			}
			start = i + 1
			next := &mavenItem{kind: mavenList}
			list.items = append(list.items, next)
			list = next
			stack = append(stack, list)
		case isDigit(c):
			if !isDigitRun && i > start {
				list.items = append(list.items, newMavenString(v[start:i], true))
				start = i
				next := &mavenItem{kind: mavenList}
				list.items = append(list.items, next)
				list = next
				stack = append(stack, list)
			}
			isDigitRun = true
		default:
			if isDigitRun && i > start {
				list.items = append(list.items, newMavenNumberOrString(v[start:i], true, false))
				start = i
				next := &mavenItem{kind: mavenList}
				list.items = append(list.items, next)
				list = next
				stack = append(stack, list)
			}
			isDigitRun = false
		}
	}
	if len(v) > start {
		list.items = append(list.items, newMavenNumberOrString(v[start:], isDigitRun, false))
	}
	for i := len(stack) - 1; i >= 0; i-- {
		stack[i].normalize()
	}
	return root
}

// compare orders it against other; a nil other is the end of a list.
func (it *mavenItem) compare(other *mavenItem) int {
	switch it.kind {
	case mavenInt:
		if other == nil {
			if it.value == "" {
				return 0
			}
			return 1
		}
		switch other.kind {
		case mavenInt:
			return compareNumbers(it.value, other.value)
		default:
			return 1
		}
	case mavenString:
		if other == nil {
			return strings.Compare(mavenQualifierKey(it.value), mavenQualifierKey(""))
		}
		switch other.kind {
		case mavenString:
			return strings.Compare(mavenQualifierKey(it.value), mavenQualifierKey(other.value))
		default:
			return -1
		}
	default:
		if other == nil {
			if len(it.items) == 0 {
				return 0
			}
			return it.items[0].compare(nil)
		}
		switch other.kind {
		case mavenInt:
			return -1
		case mavenString:
			return 1
		}
		for i := 0; i < len(it.items) || i < len(other.items); i++ {
			var l, r *mavenItem
			if i < len(it.items) {
				l = it.items[i]
			}
			if i < len(other.items) {
				r = other.items[i]
			}
			var c int
			if l == nil {
				if r == nil {
					c = 0
				} else {
					c = -r.compare(nil)
				}
			} else {
				c = l.compare(r)
			}
			if c != 0 {
				return c
			}
		}
		return 0
	}
}
