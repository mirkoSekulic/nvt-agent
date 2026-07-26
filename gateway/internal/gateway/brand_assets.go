package gateway

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"image/png"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

const (
	brandMarkPath      = "/healthz/branding/nvt-agent-mark-64.png"
	brandTouchIconPath = "/healthz/branding/nvt-agent-mark-192.png"
	brandFaviconPath   = "/healthz/branding/favicon.ico"
	brandMarkFilename  = "nvt-agent-mark-64.png"
	brandTouchFilename = "nvt-agent-mark-192.png"
	brandIconFilename  = "favicon.ico"
	maxBrandAssetBytes = 512 * 1024
)

//go:embed branding/nvt-agent-mark-64.png
var brandMarkPNG []byte

//go:embed branding/nvt-agent-mark-192.png
var brandTouchIconPNG []byte

//go:embed branding/favicon.ico
var brandFaviconICO []byte

type brandAssets struct {
	mark      []byte
	touchIcon []byte
	favicon   []byte
}

func loadBrandAssets(dir string) (brandAssets, error) {
	if dir == "" {
		return brandAssets{mark: brandMarkPNG, touchIcon: brandTouchIconPNG, favicon: brandFaviconICO}, nil
	}
	mark, err := loadBrandPNG(filepath.Join(dir, brandMarkFilename), 64)
	if err != nil {
		return brandAssets{}, err
	}
	touch, err := loadBrandPNG(filepath.Join(dir, brandTouchFilename), 192)
	if err != nil {
		return brandAssets{}, err
	}
	favicon, err := loadBoundedBrandFile(filepath.Join(dir, brandIconFilename))
	if err != nil {
		return brandAssets{}, err
	}
	if !validICO(favicon) {
		return brandAssets{}, fmt.Errorf("%s must be an ICO image", brandIconFilename)
	}
	return brandAssets{mark: mark, touchIcon: touch, favicon: favicon}, nil
}

func validICO(content []byte) bool {
	if len(content) < 6 || !bytes.Equal(content[:4], []byte{0, 0, 1, 0}) {
		return false
	}
	count := int(binary.LittleEndian.Uint16(content[4:6]))
	if count == 0 || count > 32 || len(content) < 6+count*16 {
		return false
	}
	for index := 0; index < count; index++ {
		entry := content[6+index*16 : 6+(index+1)*16]
		size := uint64(binary.LittleEndian.Uint32(entry[8:12]))
		offset := uint64(binary.LittleEndian.Uint32(entry[12:16]))
		if size == 0 || offset < uint64(6+count*16) || offset+size > uint64(len(content)) {
			return false
		}
	}
	return true
}

func loadBrandPNG(filename string, size int) ([]byte, error) {
	content, err := loadBoundedBrandFile(filename)
	if err != nil {
		return nil, err
	}
	config, err := png.DecodeConfig(bytes.NewReader(content))
	if err != nil || config.Width != size || config.Height != size {
		return nil, fmt.Errorf("%s must be a %dx%d PNG", filepath.Base(filename), size, size)
	}
	decoded, err := png.Decode(bytes.NewReader(content))
	if err != nil || decoded.Bounds().Dx() != size || decoded.Bounds().Dy() != size {
		return nil, fmt.Errorf("%s must be a %dx%d PNG", filepath.Base(filename), size, size)
	}
	return content, nil
}

func loadBoundedBrandFile(filename string) ([]byte, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(filename), err)
	}
	if len(content) == 0 || len(content) > maxBrandAssetBytes {
		return nil, fmt.Errorf("%s must contain between 1 and %d bytes", filepath.Base(filename), maxBrandAssetBytes)
	}
	return content, nil
}

func (s *Server) serveBrandAsset(w http.ResponseWriter, r *http.Request) bool {
	var content []byte
	var contentType string
	switch r.URL.Path {
	case s.config.mountedPath(brandMarkPath):
		content, contentType = s.branding.mark, "image/png"
	case s.config.mountedPath(brandTouchIconPath):
		content, contentType = s.branding.touchIcon, "image/png"
	case s.config.mountedPath(brandFaviconPath):
		content, contentType = s.branding.favicon, "image/x-icon"
	default:
		return false
	}
	if r.URL.EscapedPath() != r.URL.Path {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(content)
	}
	return true
}
