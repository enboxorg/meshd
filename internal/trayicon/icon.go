// Package trayicon renders the meshd status icons used by the menu-bar app.
//
// The geometry is the monochrome form of the meshd brand mark: five outer
// nodes connected to a central node. macOS receives a black-and-alpha template
// PNG so the system can adapt it to the menu-bar appearance. Windows receives
// a multi-resolution ICO with the brand colors.
package trayicon

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

const templateSize = 32

var windowsSizes = [...]int{16, 20, 24, 32, 40, 48, 64}

// TemplatePNG returns a macOS template icon for the requested connection
// state. Its pixels are black with varying alpha, as required for a native
// template image.
func TemplatePNG(connected bool) []byte {
	return encodePNG(render(templateSize, connected, false))
}

// WindowsICO returns a multi-resolution Windows notification-area icon for
// the requested connection state.
func WindowsICO(connected bool) []byte {
	images := make([][]byte, 0, len(windowsSizes))
	for _, size := range windowsSizes {
		images = append(images, encodePNG(render(size, connected, true)))
	}

	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(&out, binary.LittleEndian, uint16(1)) // icon
	_ = binary.Write(&out, binary.LittleEndian, uint16(len(images)))

	offset := uint32(6 + 16*len(images))
	for i, data := range images {
		size := windowsSizes[i]
		width, height := byte(size), byte(size)
		if size == 256 {
			width, height = 0, 0
		}
		out.WriteByte(width)
		out.WriteByte(height)
		out.WriteByte(0)                                        // palette colors
		out.WriteByte(0)                                        // reserved
		_ = binary.Write(&out, binary.LittleEndian, uint16(1))  // planes
		_ = binary.Write(&out, binary.LittleEndian, uint16(32)) // bits per pixel
		_ = binary.Write(&out, binary.LittleEndian, uint32(len(data)))
		_ = binary.Write(&out, binary.LittleEndian, offset)
		offset += uint32(len(data))
	}
	for _, data := range images {
		out.Write(data)
	}
	return out.Bytes()
}

type point struct {
	x float64
	y float64
}

func render(size int, connected, colored bool) *image.RGBA {
	const scale = 4
	hiSize := size * scale
	img := image.NewRGBA(image.Rect(0, 0, hiSize, hiSize))

	outer := []point{
		{0.50, 0.12},
		{0.84, 0.37},
		{0.71, 0.80},
		{0.29, 0.80},
		{0.16, 0.37},
	}
	center := point{0.50, 0.49}

	edgeColor := color.RGBA{0, 0, 0, 155}
	outerColor := color.RGBA{0, 0, 0, 255}
	centerColor := color.RGBA{0, 0, 0, 255}
	slashColor := color.RGBA{0, 0, 0, 255}
	if colored {
		edgeColor = color.RGBA{77, 218, 200, 150}
		outerColor = color.RGBA{77, 218, 200, 255}
		centerColor = color.RGBA{255, 159, 107, 255}
		slashColor = color.RGBA{230, 86, 86, 255}
	}
	if !connected {
		edgeColor.A = 70
		outerColor = color.RGBA{112, 116, 125, 205}
		centerColor = color.RGBA{112, 116, 125, 170}
		if !colored {
			outerColor = color.RGBA{0, 0, 0, 155}
			centerColor = color.RGBA{0, 0, 0, 120}
		}
	}

	lineWidth := float64(hiSize) * 0.055
	for i := range outer {
		drawLine(img, scalePoint(outer[i], hiSize), scalePoint(outer[(i+1)%len(outer)], hiSize), lineWidth, edgeColor)
		drawLine(img, scalePoint(center, hiSize), scalePoint(outer[i], hiSize), lineWidth, edgeColor)
	}

	outerRadius := float64(hiSize) * 0.095
	centerRadius := float64(hiSize) * 0.112
	for _, p := range outer {
		drawCircle(img, scalePoint(p, hiSize), outerRadius, outerColor)
	}
	drawCircle(img, scalePoint(center, hiSize), centerRadius, centerColor)

	if !connected {
		from := scalePoint(point{0.20, 0.18}, hiSize)
		to := scalePoint(point{0.80, 0.82}, hiSize)
		if colored {
			drawLine(img, from, to, float64(hiSize)*0.105, color.RGBA{255, 255, 255, 235})
		} else {
			clearLine(img, from, to, float64(hiSize)*0.105)
		}
		drawLine(img, from, to, float64(hiSize)*0.060, slashColor)
	}

	return downsample(img, size)
}

func scalePoint(p point, size int) point {
	return point{p.x * float64(size-1), p.y * float64(size-1)}
}

func drawLine(img *image.RGBA, from, to point, width float64, c color.RGBA) {
	minX := int(math.Floor(math.Min(from.x, to.x) - width))
	maxX := int(math.Ceil(math.Max(from.x, to.x) + width))
	minY := int(math.Floor(math.Min(from.y, to.y) - width))
	maxY := int(math.Ceil(math.Max(from.y, to.y) + width))
	radius := width / 2
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			if distanceToSegment(float64(x)+0.5, float64(y)+0.5, from, to) <= radius {
				blend(img, x, y, c)
			}
		}
	}
}

func clearLine(img *image.RGBA, from, to point, width float64) {
	minX := int(math.Floor(math.Min(from.x, to.x) - width))
	maxX := int(math.Ceil(math.Max(from.x, to.x) + width))
	minY := int(math.Floor(math.Min(from.y, to.y) - width))
	maxY := int(math.Ceil(math.Max(from.y, to.y) + width))
	radius := width / 2
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			if image.Pt(x, y).In(img.Bounds()) && distanceToSegment(float64(x)+0.5, float64(y)+0.5, from, to) <= radius {
				img.SetRGBA(x, y, color.RGBA{})
			}
		}
	}
}

func drawCircle(img *image.RGBA, center point, radius float64, c color.RGBA) {
	minX := int(math.Floor(center.x - radius))
	maxX := int(math.Ceil(center.x + radius))
	minY := int(math.Floor(center.y - radius))
	maxY := int(math.Ceil(center.y + radius))
	radiusSquared := radius * radius
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			dx := float64(x) + 0.5 - center.x
			dy := float64(y) + 0.5 - center.y
			if dx*dx+dy*dy <= radiusSquared {
				blend(img, x, y, c)
			}
		}
	}
}

func distanceToSegment(x, y float64, from, to point) float64 {
	dx, dy := to.x-from.x, to.y-from.y
	if dx == 0 && dy == 0 {
		return math.Hypot(x-from.x, y-from.y)
	}
	t := ((x-from.x)*dx + (y-from.y)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(x-(from.x+t*dx), y-(from.y+t*dy))
}

func blend(img *image.RGBA, x, y int, src color.RGBA) {
	if !image.Pt(x, y).In(img.Bounds()) {
		return
	}
	dst := img.RGBAAt(x, y)
	sa := uint32(src.A)
	da := uint32(dst.A) * (255 - sa) / 255
	outA := sa + da
	if outA == 0 {
		return
	}
	mix := func(s, d uint8) uint8 {
		return uint8((uint32(s)*sa + uint32(d)*da) / outA)
	}
	img.SetRGBA(x, y, color.RGBA{mix(src.R, dst.R), mix(src.G, dst.G), mix(src.B, dst.B), uint8(outA)})
}

func downsample(src *image.RGBA, size int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	scale := src.Bounds().Dx() / size
	area := uint32(scale * scale)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a uint32
			for sy := 0; sy < scale; sy++ {
				for sx := 0; sx < scale; sx++ {
					c := src.RGBAAt(x*scale+sx, y*scale+sy)
					r += uint32(c.R)
					g += uint32(c.G)
					b += uint32(c.B)
					a += uint32(c.A)
				}
			}
			dst.SetRGBA(x, y, color.RGBA{uint8(r / area), uint8(g / area), uint8(b / area), uint8(a / area)})
		}
	}
	return dst
}

func encodePNG(img image.Image) []byte {
	var out bytes.Buffer
	_ = png.Encode(&out, img)
	return out.Bytes()
}
