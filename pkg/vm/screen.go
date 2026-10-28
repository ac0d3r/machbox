package vm

/*
#cgo LDFLAGS: -framework CoreGraphics
#include <CoreGraphics/CoreGraphics.h>
*/
import "C"

import "math"

// Share of the main display a window may take: the rest is left for the
// menu bar, the Dock and the window's title bar and toolbar.
const (
	windowMaxWidth  = 0.9
	windowMaxHeight = 0.8
)

// fitWindow scales width×height down, keeping its aspect ratio, to fit the
// main display. The guest display follows the window size (vz reconfigures
// it on macOS 14+), so the window, not the configured resolution, decides
// what fits on screen.
func fitWindow(width, height float64) (w, h float64) {
	bounds := C.CGDisplayBounds(C.CGMainDisplayID()) // in points, like window sizes
	sw, sh := float64(bounds.size.width), float64(bounds.size.height)
	if sw <= 0 || sh <= 0 {
		return width, height
	}
	scale := math.Min(1, math.Min(sw*windowMaxWidth/width, sh*windowMaxHeight/height))
	return math.Floor(width * scale), math.Floor(height * scale)
}
