package dashboard

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
)

func TestChartCellWidthsAndBoundaries(t *testing.T) {
	start := epoch()
	points := []Point{{At: start, Value: 10, Valid: true}, {At: start.Add(time.Second), Value: 0, Valid: true}, {At: start.Add(2 * time.Second), Value: 5, Valid: true}}
	for _, style := range []string{"braille", "block", "ascii", "invalid-default"} {
		for _, width := range []int{1, 2, 10, 79, 120} {
			for _, height := range []int{1, 2, 6} {
				rendered := Chart(points, start, start.Add(2*time.Second), width, height, style)
				lines := strings.Split(rendered, "\n")
				if len(lines) != height {
					t.Fatalf("%s %dx%d: got %d lines", style, width, height, len(lines))
				}
				for _, line := range lines {
					if got := ansi.StringWidth(line); got != width {
						t.Fatalf("%s chart width %d, want %d: %q", style, got, width, line)
					}
					if style == "ascii" {
						for _, ch := range line {
							if ch > 127 {
								t.Fatalf("non-ASCII fallback: %q", line)
							}
						}
					}
				}
			}
		}
	}
	for _, size := range [][2]int{{0, 5}, {5, 0}, {-1, 1}, {1, -1}} {
		if result := Chart(points, start, start, size[0], size[1], "braille"); result != "" {
			t.Fatalf("non-positive dimensions returned %q", result)
		}
	}
}

func TestChartUsesTimestampsWithoutFillingMissingTime(t *testing.T) {
	start := epoch()
	points := []Point{{At: start.Add(2 * time.Second), Value: 10, Valid: true}, {At: start.Add(3 * time.Second), Value: 10, Valid: true}}
	got := Chart(points, start, start.Add(10*time.Second), 11, 1, "ascii")
	if got != "  **       " {
		t.Fatalf("points stretched over their own range instead of the window: %q", got)
	}
	points = []Point{{At: start, Value: 10, Valid: true}, {At: start.Add(10 * time.Second), Value: 10, Valid: true}}
	if got = Chart(points, start, start.Add(10*time.Second), 11, 1, "ascii"); got != "*         *" {
		t.Fatalf("long missing interval was interpolated: %q", got)
	}
	points = []Point{{At: start, Value: 10, Valid: true}, {At: start.Add(time.Second)}, {At: start.Add(3 * time.Second), Value: 10, Valid: true}}
	if got = Chart(points, start, start.Add(10*time.Second), 11, 1, "ascii"); got != "*  *       " {
		t.Fatalf("explicit gap was interpolated: %q", got)
	}
}

func TestChartZeroIsObservedButInvalidIsBlank(t *testing.T) {
	start := epoch()
	points := []Point{{At: start, Value: 0, Valid: true}, {At: start.Add(time.Second)}, {At: start.Add(2 * time.Second), Value: math.NaN(), Valid: true}}
	if got := Chart(points, start, start.Add(2*time.Second), 3, 3, "ascii"); got != "   \n   \n*  " {
		t.Fatalf("zero, gap, or invalid number plotted incorrectly: %q", got)
	}
	if got := Chart(nil, start, start.Add(time.Second), 3, 2, "braille"); got != "   \n   " {
		t.Fatalf("absent data fabricated a baseline: %q", got)
	}
	if got := Chart(points, start, start, 3, 2, "block"); got != "   \n   " {
		t.Fatalf("empty time interval fabricated samples: %q", got)
	}
}
