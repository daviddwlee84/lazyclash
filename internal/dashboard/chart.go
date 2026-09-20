package dashboard

import (
	"math"
	"strings"
	"time"
)

// Chart draws positive-valued telemetry against real time, using a zero
// baseline and a shared maximum for this series. Every output line occupies
// exactly width cells. Missing samples and gaps longer than StaleAfter remain
// empty; an observed zero draws at the baseline. Styles: braille, block, ascii.
func Chart(points []Point, start, end time.Time, width, height int, style string) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	xScale, yScale := 2, 4
	switch style {
	case "ascii":
		xScale, yScale = 1, 1
	case "block":
		xScale, yScale = 1, 2
	default:
		style = "braille"
	}
	pixelWidth, pixelHeight := width*xScale, height*yScale
	pixels := make([]bool, pixelWidth*pixelHeight)
	maximum := 0.0
	for _, point := range points {
		if point.Valid && !point.At.Before(start) && !point.At.After(end) && finite(point.Value) {
			maximum = max(maximum, point.Value)
		}
	}
	if maximum == 0 {
		maximum = 1
	}
	duration := end.Sub(start)
	if duration > 0 {
		var previous Point
		var previousX, previousY int
		for _, point := range points {
			if !point.Valid || point.At.Before(start) || point.At.After(end) || !finite(point.Value) {
				previous.Valid = false
				continue
			}
			x := int(math.Round(float64(point.At.Sub(start)) / float64(duration) * float64(pixelWidth-1)))
			y := pixelHeight - 1 - int(math.Round(point.Value/maximum*float64(pixelHeight-1)))
			x, y = min(max(x, 0), pixelWidth-1), min(max(y, 0), pixelHeight-1)
			pixels[y*pixelWidth+x] = true
			if previous.Valid && !point.At.Before(previous.At) && point.At.Sub(previous.At) <= StaleAfter {
				line(pixels, pixelWidth, previousX, previousY, x, y)
			}
			previous, previousX, previousY = point, x, y
		}
	}
	var result strings.Builder
	for cellY := 0; cellY < height; cellY++ {
		if cellY > 0 {
			result.WriteByte('\n')
		}
		for cellX := 0; cellX < width; cellX++ {
			switch style {
			case "ascii":
				if pixels[cellY*pixelWidth+cellX] {
					result.WriteByte('*')
				} else {
					result.WriteByte(' ')
				}
			case "block":
				top := pixels[cellY*2*pixelWidth+cellX]
				bottom := pixels[(cellY*2+1)*pixelWidth+cellX]
				switch {
				case top && bottom:
					result.WriteRune('█')
				case top:
					result.WriteRune('▀')
				case bottom:
					result.WriteRune('▄')
				default:
					result.WriteByte(' ')
				}
			default:
				var dots rune
				bits := [4][2]rune{{1, 8}, {2, 16}, {4, 32}, {64, 128}}
				for dy := 0; dy < 4; dy++ {
					for dx := 0; dx < 2; dx++ {
						if pixels[(cellY*4+dy)*pixelWidth+cellX*2+dx] {
							dots |= bits[dy][dx]
						}
					}
				}
				if dots == 0 {
					result.WriteByte(' ')
				} else {
					result.WriteRune(0x2800 + dots)
				}
			}
		}
	}
	return result.String()
}

func Sparkline(points []Point, start, end time.Time, width int, style string) string {
	return Chart(points, start, end, width, 1, style)
}

func finite(value float64) bool { return value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0) }

func line(pixels []bool, width, x0, y0, x1, y1 int) {
	dx, dy := abs(x1-x0), -abs(y1-y0)
	sx, sy := 1, 1
	if x0 > x1 {
		sx = -1
	}
	if y0 > y1 {
		sy = -1
	}
	err := dx + dy
	for {
		pixels[y0*width+x0] = true
		if x0 == x1 && y0 == y1 {
			return
		}
		twice := 2 * err
		if twice >= dy {
			err += dy
			x0 += sx
		}
		if twice <= dx {
			err += dx
			y0 += sy
		}
	}
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
