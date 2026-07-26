package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPublicBrandAssetsRootAndMountedPaths(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*Config)
		origin    string
		basePath  string
	}{
		{name: "subdomain", origin: "http://agents.localhost"},
		{
			name: "root path",
			configure: func(config *Config) {
				config.Routing.Mode = routingModePath
				config.PublicURL = "https://agents.example.com"
			},
			origin: "https://agents.example.com",
		},
		{
			name: "prefixed path",
			configure: func(config *Config) {
				config.Routing.Mode = routingModePath
				config.PublicURL = "https://staging.example.com/agents"
			},
			origin:   "https://staging.example.com",
			basePath: "/agents",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090, Auth: AuthConfig{Mode: authModeNone}}
			if test.configure != nil {
				test.configure(&config)
			}
			server := mustNewServer(t, config, fakeClient(t))
			for _, asset := range []struct {
				path        string
				contentType string
				content     []byte
			}{
				{path: brandMarkPath, contentType: "image/png", content: brandMarkPNG},
				{path: brandTouchIconPath, contentType: "image/png", content: brandTouchIconPNG},
				{path: brandFaviconPath, contentType: "image/x-icon", content: brandFaviconICO},
			} {
				assetURL := test.origin + test.basePath + asset.path
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					response := httptest.NewRecorder()
					server.ServeHTTP(response, httptest.NewRequest(method, assetURL, nil))
					if response.Code != http.StatusOK || response.Header().Get("Content-Type") != asset.contentType || response.Header().Get("Cache-Control") != "public, max-age=86400" {
						t.Fatalf("%s %s status=%d type=%q cache=%q", method, assetURL, response.Code, response.Header().Get("Content-Type"), response.Header().Get("Cache-Control"))
					}
					if response.Header().Get("X-Content-Type-Options") != "nosniff" {
						t.Fatalf("%s missing nosniff", assetURL)
					}
					if response.Header().Get("Content-Length") != strconv.Itoa(len(asset.content)) {
						t.Fatalf("%s content length=%q", assetURL, response.Header().Get("Content-Length"))
					}
					if method == http.MethodGet && !bytes.Equal(response.Body.Bytes(), asset.content) {
						t.Fatalf("GET %s returned unexpected bytes", assetURL)
					}
					if method == http.MethodHead && response.Body.Len() != 0 {
						t.Fatalf("HEAD %s returned %d body bytes", assetURL, response.Body.Len())
					}
				}
			}

			post := httptest.NewRecorder()
			server.ServeHTTP(post, httptest.NewRequest(http.MethodPost, test.origin+test.basePath+brandMarkPath, nil))
			if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Allow") != "GET, HEAD" {
				t.Fatalf("asset POST status=%d allow=%q", post.Code, post.Header().Get("Allow"))
			}
			trailing := httptest.NewRecorder()
			server.ServeHTTP(trailing, httptest.NewRequest(http.MethodGet, test.origin+test.basePath+brandMarkPath+"/extra", nil))
			if trailing.Header().Get("Content-Type") == "image/png" || bytes.Equal(trailing.Body.Bytes(), brandMarkPNG) {
				t.Fatal("non-allowlisted asset path served embedded bytes")
			}
			if test.basePath != "" {
				wrongOrigin := httptest.NewRecorder()
				server.ServeHTTP(wrongOrigin, httptest.NewRequest(http.MethodGet, "https://wrong.example"+test.basePath+brandMarkPath, nil))
				if wrongOrigin.Code != http.StatusNotFound {
					t.Fatalf("wrong-origin asset status=%d", wrongOrigin.Code)
				}
			}
		})
	}
}

func TestBrandAssetsCanBeLoadedFromFixedDirectory(t *testing.T) {
	dir := t.TempDir()
	mark := writeTestBrandPNG(t, dir, brandMarkFilename, 64, color.RGBA{R: 12, G: 34, B: 56, A: 255})
	touch := writeTestBrandPNG(t, dir, brandTouchFilename, 192, color.RGBA{R: 78, G: 90, B: 12, A: 255})
	favicon := append([]byte(nil), brandFaviconICO...)
	if err := os.WriteFile(filepath.Join(dir, brandIconFilename), favicon, 0o600); err != nil {
		t.Fatal(err)
	}
	config := Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090, BrandingDir: dir, Auth: AuthConfig{Mode: authModeNone}}
	server := mustNewServer(t, config, fakeClient(t))
	for _, asset := range []struct {
		path    string
		content []byte
	}{
		{path: brandMarkPath, content: mark},
		{path: brandTouchIconPath, content: touch},
		{path: brandFaviconPath, content: favicon},
	} {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://agents.localhost"+asset.path, nil))
		if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), asset.content) {
			t.Fatalf("GET %s did not serve configured branding", asset.path)
		}
	}
}

func TestFormerBrandPathsRemainAvailableForConfiguredCallbacks(t *testing.T) {
	formerPaths := []string{
		"/oauth2/branding/nvt-agent-mark-64.png",
		"/oauth2/branding/nvt-agent-mark-192.png",
		"/oauth2/branding/favicon.ico",
	}
	for _, authMode := range []string{authModeOAuth2, authModeOIDC} {
		for _, mount := range []struct {
			name      string
			publicURL string
			origin    string
			basePath  string
		}{
			{name: "root", publicURL: "https://agents.example.com", origin: "https://agents.example.com"},
			{name: "mounted", publicURL: "https://staging.example.com/agents", origin: "https://staging.example.com", basePath: "/agents"},
		} {
			for _, callbackPath := range formerPaths {
				name := authMode + "/" + mount.name + "/" + filepath.Base(callbackPath)
				t.Run(name, func(t *testing.T) {
					var config Config
					if authMode == authModeOIDC {
						provider := oidcDiscoveryServer(t)
						config = oidcTestConfig(provider.URL)
						config.Auth.OIDC.CallbackPath = callbackPath
					} else {
						config = authenticatedTestConfig()
						config.Auth.OAuth2.CallbackPath = callbackPath
						config.Auth.Session.Secure = true
					}
					config.Routing.Mode = routingModePath
					config.PublicURL = mount.publicURL
					server := mustNewServer(t, config, fakeClient(t))
					response := httptest.NewRecorder()
					server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, mount.origin+mount.basePath+callbackPath+"?code=test", nil))
					if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "login state expired") {
						t.Fatalf("callback %s status=%d type=%q body=%q", callbackPath, response.Code, response.Header().Get("Content-Type"), response.Body.String())
					}
					if strings.HasPrefix(response.Header().Get("Content-Type"), "image/") {
						t.Fatalf("callback %s was shadowed by a branding asset", callbackPath)
					}
				})
			}
		}
	}
}

func TestBrandAssetOverrideFailsClosed(t *testing.T) {
	validConfig := Config{BaseDomain: "agents.localhost", ListenAddr: ":8080", DefaultTargetPort: 4090, Auth: AuthConfig{Mode: authModeNone}}
	for _, test := range []struct {
		name    string
		prepare func(*testing.T, string)
		want    string
	}{
		{name: "missing files", want: brandMarkFilename},
		{
			name: "wrong dimensions",
			prepare: func(t *testing.T, dir string) {
				writeTestBrandPNG(t, dir, brandMarkFilename, 32, color.Black)
			},
			want: "64x64 PNG",
		},
		{
			name: "huge declared dimensions",
			prepare: func(t *testing.T, dir string) {
				content := writeTestBrandPNG(t, dir, brandMarkFilename, 64, color.Black)
				binary.BigEndian.PutUint32(content[16:20], 1_000_000)
				binary.BigEndian.PutUint32(content[20:24], 1_000_000)
				binary.BigEndian.PutUint32(content[29:33], crc32.ChecksumIEEE(content[12:29]))
				if err := os.WriteFile(filepath.Join(dir, brandMarkFilename), content, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "64x64 PNG",
		},
		{
			name: "invalid favicon",
			prepare: func(t *testing.T, dir string) {
				writeTestBrandPNG(t, dir, brandMarkFilename, 64, color.Black)
				writeTestBrandPNG(t, dir, brandTouchFilename, 192, color.Black)
				if err := os.WriteFile(filepath.Join(dir, brandIconFilename), []byte("not an icon"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "must be an ICO image",
		},
		{
			name: "oversized favicon",
			prepare: func(t *testing.T, dir string) {
				writeTestBrandPNG(t, dir, brandMarkFilename, 64, color.Black)
				writeTestBrandPNG(t, dir, brandTouchFilename, 192, color.Black)
				if err := os.WriteFile(filepath.Join(dir, brandIconFilename), make([]byte, maxBrandAssetBytes+1), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "between 1 and",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if test.prepare != nil {
				test.prepare(t, dir)
			}
			config := validConfig
			config.BrandingDir = dir
			_, err := NewServer(config, fakeClient(t), "default")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NewServer error=%v, want %q", err, test.want)
			}
		})
	}
	validConfig.BrandingDir = "relative"
	if err := validConfig.Validate(); err == nil || !strings.Contains(err.Error(), "absolute canonical path") {
		t.Fatalf("relative brandingDir error=%v", err)
	}
}

func writeTestBrandPNG(t *testing.T, dir, name string, size int, fill color.Color) []byte {
	t.Helper()
	var content bytes.Buffer
	canvas := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(canvas, canvas.Bounds(), &image.Uniform{C: fill}, image.Point{}, draw.Src)
	if err := png.Encode(&content, canvas); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), content.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return content.Bytes()
}

func TestDashboardBrandMetadataUsesMountedPaths(t *testing.T) {
	config := Config{
		PublicURL: "https://staging.example.com/agents", ListenAddr: ":8080", DefaultTargetPort: 4090,
		Routing: RoutingConfig{Mode: routingModePath}, Auth: AuthConfig{Mode: authModeNone},
	}
	server := mustNewServer(t, config, fakeClient(t))
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://staging.example.com/agents/", nil))
	body := response.Body.String()
	for _, expected := range []string{
		`<title>NVT Agent</title>`,
		`rel="icon" href="/agents/healthz/branding/favicon.ico"`,
		`rel="apple-touch-icon" href="/agents/healthz/branding/nvt-agent-mark-192.png"`,
		`img src="/agents/healthz/branding/nvt-agent-mark-64.png"`,
		`class="brand-name">NVT Agent`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("dashboard missing %q: %s", expected, body)
		}
	}
}

func TestSignInBrandMetadataUsesMountedPaths(t *testing.T) {
	config := authenticatedTestConfig()
	config.PublicURL = "https://staging.example.com/agents"
	config.Routing.Mode = routingModePath
	config.Auth.Session.Secure = true
	server := mustNewServer(t, config, fakeClient(t))
	response := serveBrowserGet(t, server, "https://staging.example.com/agents/")
	body := response.Body.String()
	for _, expected := range []string{
		`<title>Sign in · NVT Agent</title>`,
		`rel="icon" href="/agents/healthz/branding/favicon.ico"`,
		`rel="apple-touch-icon" href="/agents/healthz/branding/nvt-agent-mark-192.png"`,
		`img src="/agents/healthz/branding/nvt-agent-mark-64.png"`,
		`class="brand">NVT Agent`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("sign-in page missing %q: %s", expected, body)
		}
	}
}

func TestEmbeddedBrandAssetsMatchCanonicalCopies(t *testing.T) {
	for _, asset := range []struct {
		canonical string
		embedded  []byte
	}{
		{canonical: "nvt-agent-mark-64.png", embedded: brandMarkPNG},
		{canonical: "nvt-agent-mark-192.png", embedded: brandTouchIconPNG},
		{canonical: "favicon.ico", embedded: brandFaviconICO},
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "assets", "branding", asset.canonical))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, asset.embedded) {
			t.Fatalf("embedded %s drifted from canonical generation", asset.canonical)
		}
	}
}

func TestCanonicalBrandSourceHash(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "assets", "branding", "source", "nvt-logo-source.png"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != "ecc3b84860236edc1b2550a1e89ffb38c5a145639cff26d8b05e3c0aff754212" {
		t.Fatalf("canonical source SHA-256=%s", got)
	}
}

func TestBrandAssetsUseExistingReservedNamespace(t *testing.T) {
	if !reservedGatewayPath("healthz") {
		t.Fatal("branding namespace must remain below the existing healthz reservation")
	}
	for _, key := range []string{"assets", "favicon.ico"} {
		if reservedGatewayPath(key) {
			t.Fatalf("previously valid access key %q became reserved", key)
		}
	}
}
