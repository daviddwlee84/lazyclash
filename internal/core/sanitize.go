package core

import (
	"strings"
	"unicode"
)

// Sanitize removes terminal escape sequences and control characters from remote
// text. Apply it only at display boundaries: original names must reach the API.
// Newlines and tabs are retained so multi-line log records remain readable.
func Sanitize(text string) string {
	const (
		plain = iota
		escaped
		csi
		stringEscape
		stringEnd
	)
	state := plain
	var out strings.Builder
	out.Grow(len(text))
	for _, r := range text {
		switch state {
		case plain:
			switch r {
			case '\x1b':
				state = escaped
			case '\u009b':
				state = csi
			case '\u009d', '\u0090', '\u009e', '\u009f':
				state = stringEscape
			default:
				if r == '\n' || r == '\t' || (!unicode.IsControl(r) && !isBidiControl(r)) {
					out.WriteRune(r)
				}
			}
		case escaped:
			switch r {
			case '[':
				state = csi
			case ']', 'P', '^', '_':
				state = stringEscape
			default:
				if r >= 0x30 && r <= 0x7e {
					state = plain
				}
			}
		case csi:
			if r >= 0x40 && r <= 0x7e {
				state = plain
			}
		case stringEscape:
			if r == '\a' || r == '\u009c' {
				state = plain
			} else if r == '\x1b' {
				state = stringEnd
			}
		case stringEnd:
			if r == '\\' || r == '\a' || r == '\u009c' {
				state = plain
			} else {
				state = stringEscape
			}
		}
	}
	return out.String()
}

func isBidiControl(r rune) bool {
	return r == '\u061c' || r == '\u200e' || r == '\u200f' || r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u2069'
}
