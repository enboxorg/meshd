package trayicon

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
)

func TestTemplatePNG(t *testing.T) {
	connected := TemplatePNG(true)
	disconnected := TemplatePNG(false)
	if bytes.Equal(connected, disconnected) {
		t.Fatal("connected and disconnected template icons are identical")
	}
	for name, data := range map[string][]byte{"connected": connected, "disconnected": disconnected} {
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("decode %s template icon: %v", name, err)
		}
		if got := img.Bounds().Size(); got.X != templateSize || got.Y != templateSize {
			t.Fatalf("%s template size = %v, want %dx%d", name, got, templateSize, templateSize)
		}
		for y := img.Bounds().Min.Y; y < img.Bounds().Max.Y; y++ {
			for x := img.Bounds().Min.X; x < img.Bounds().Max.X; x++ {
				r, g, b, _ := img.At(x, y).RGBA()
				if r != 0 || g != 0 || b != 0 {
					t.Fatalf("%s template pixel at %d,%d is not black", name, x, y)
				}
			}
		}
	}
}

func TestWindowsICOContainsAllResolutions(t *testing.T) {
	icon := WindowsICO(true)
	if len(icon) < 6 {
		t.Fatalf("ICO length = %d, want header", len(icon))
	}
	if reserved := binary.LittleEndian.Uint16(icon[0:2]); reserved != 0 {
		t.Fatalf("ICO reserved = %d, want 0", reserved)
	}
	if kind := binary.LittleEndian.Uint16(icon[2:4]); kind != 1 {
		t.Fatalf("ICO type = %d, want 1", kind)
	}
	if count := int(binary.LittleEndian.Uint16(icon[4:6])); count != len(windowsSizes) {
		t.Fatalf("ICO image count = %d, want %d", count, len(windowsSizes))
	}
	if bytes.Equal(icon, WindowsICO(false)) {
		t.Fatal("connected and disconnected Windows icons are identical")
	}
}
