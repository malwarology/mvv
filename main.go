package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const toolName = "mvv"

var toolVersion = "dev"

type lastState struct {
	TypeLabel    string `json:"type"`
	SubTypeLabel string `json:"stype,omitempty"`
	Ext          string `json:"ext,omitempty"`
	HasExt       bool   `json:"has_ext"`
	UnixTime     int64  `json:"unix_time"`
}

type sidecarMetadata struct {
	ToolName           string `json:"tool_name"`
	ToolVersion        string `json:"tool_version"`
	TimestampRFC3339   string `json:"timestamp"`
	OriginalFilename   string `json:"original_filename"`
	OriginalPathAbs    string `json:"original_path_abs"`
	OriginalPermOctal  string `json:"original_perm_octal"`
	OriginalModeString string `json:"original_mode_string"`
}

func usage() {
	//goland:noinspection GoUnhandledErrorResult
	fmt.Fprintf(os.Stderr, `%s — malware sample filename normalizer

Usage:
  %s [options] <file...>

Options:
  -h, --help
        Show this help and exit

  -v, --version
        Show version and exit

  -D, --debug
        Dry-run only (do not rename files; still prints planned actions)

  -t, --type <string>
        Primary type label (required on first run)

  -s, --stype <string>
        Optional subtype label

  -e, --ext <string>
        Force file extension (with or without leading dot)

  -j, --json
        Write sidecar JSON metadata alongside the renamed file

  -r
        Reuse last type

  -rr
        Reuse last type, subtype, and extension override
`, toolName, toolName)
}

func statePath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfgDir, toolName, "state.json"), nil
}

func loadState() (*lastState, error) {
	p, err := statePath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var st lastState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("failed to parse state file %q: %w", p, err)
	}
	return &st, nil
}

func saveState(st *lastState) error {
	p, err := statePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	st.UnixTime = time.Now().Unix()

	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(p, b, 0o600)
}

func normalizeExt(ext string) (string, bool) {
	if ext == "" {
		return "", false
	}
	if ext[0] == '.' {
		ext = ext[1:]
	}
	if ext == "" {
		return "", false
	}
	return ext, true
}

func validLabel(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

func absPath(p string) (string, error) {
	a, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(a), nil
}

func fileSHA256Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum), nil
}

func normalizedStem(typeLabel string, shaPrefix string, subTypeLabel string) string {
	if subTypeLabel != "" {
		return fmt.Sprintf("%s_%s_%s", typeLabel, shaPrefix, subTypeLabel)
	}
	return fmt.Sprintf("%s_%s", typeLabel, shaPrefix)
}

func resolveUniqueName(dir string, typeLabel string, shaHex string, subTypeLabel string, extDot string) (string, int, error) {
	prefixLen := 8
	for {
		if prefixLen > len(shaHex) {
			return "", 0, fmt.Errorf("internal error: sha256 length unexpected")
		}

		stem := normalizedStem(typeLabel, shaHex[:prefixLen], subTypeLabel)
		name := stem + extDot
		target := filepath.Join(dir, name)

		_, err := os.Lstat(target)
		if err == nil {
			if prefixLen >= 64 {
				return "", 0, fmt.Errorf("unable to find unique name (sha256 prefix exhausted)")
			}
			prefixLen += 2
			continue
		}
		if os.IsNotExist(err) {
			return name, prefixLen, nil
		}
		return "", 0, err
	}
}

func startsWith(b []byte, prefix []byte) bool {
	return len(b) >= len(prefix) && bytes.Equal(b[:len(prefix)], prefix)
}

func isLikelyText(b []byte) bool {
	// Heuristic: allow common whitespace + printable ASCII; tolerate a small amount of non-text.
	if len(b) == 0 {
		return false
	}
	var bad int
	for _, c := range b {
		switch {
		case c == 0x09 || c == 0x0A || c == 0x0D: // \t \n \r
		case c >= 0x20 && c <= 0x7E:
		default:
			bad++
		}
	}
	// If more than ~5% is non-printable, treat as binary.
	return bad*20 <= len(b)
}

func sniffExtByMagic(path string) (string, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = f.Close() }()

	r := bufio.NewReaderSize(f, 8192)
	head := make([]byte, 512)
	n, _ := io.ReadFull(r, head)
	if n <= 0 {
		return "", false, nil
	}
	head = head[:n]

	// PE (MZ)
	if len(head) >= 2 && head[0] == 'M' && head[1] == 'Z' {
		return ".exe", true, nil
	}

	// ELF
	if startsWith(head, []byte{0x7F, 'E', 'L', 'F'}) {
		return ".elf", true, nil
	}

	// Mach-O (32/64, fat)
	if len(head) >= 4 {
		m := head[:4]
		switch {
		case bytes.Equal(m, []byte{0xFE, 0xED, 0xFA, 0xCE}):
			return ".macho", true, nil
		case bytes.Equal(m, []byte{0xCE, 0xFA, 0xED, 0xFE}):
			return ".macho", true, nil
		case bytes.Equal(m, []byte{0xFE, 0xED, 0xFA, 0xCF}):
			return ".macho", true, nil
		case bytes.Equal(m, []byte{0xCF, 0xFA, 0xED, 0xFE}):
			return ".macho", true, nil
		case bytes.Equal(m, []byte{0xCA, 0xFE, 0xBA, 0xBE}):
			return ".fat", true, nil
		case bytes.Equal(m, []byte{0xBE, 0xBA, 0xFE, 0xCA}):
			return ".fat", true, nil
		}
	}

	// PDF
	if startsWith(head, []byte("%PDF-")) {
		return ".pdf", true, nil
	}

	// ZIP (PK..). Could be zip/jar/apk/docx/xlsx/etc; choose .zip as neutral.
	if len(head) >= 4 && head[0] == 'P' && head[1] == 'K' && (head[2] == 0x03 || head[2] == 0x05 || head[2] == 0x07) &&
		(head[3] == 0x04 || head[3] == 0x06 || head[3] == 0x08) {
		return ".zip", true, nil
	}

	// GZIP
	if len(head) >= 2 && head[0] == 0x1F && head[1] == 0x8B {
		return ".gz", true, nil
	}

	// PNG
	if startsWith(head, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}) {
		return ".png", true, nil
	}

	// JPEG
	if len(head) >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF {
		return ".jpg", true, nil
	}

	// GIF
	if startsWith(head, []byte("GIF87a")) || startsWith(head, []byte("GIF89a")) {
		return ".gif", true, nil
	}

	// OLE/CFB (Compound File Binary)
	if startsWith(head, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}) {
		return ".ole", true, nil
	}

	// SQLite
	if startsWith(head, []byte("SQLite format 3\x00")) {
		return ".sqlite", true, nil
	}

	// RTF
	if startsWith(head, []byte("{\\rtf")) {
		return ".rtf", true, nil
	}

	trim := bytes.TrimLeft(head, "\x00\t\r\n ")
	if len(trim) > 0 {
		// HTML / XML / JSON (best-effort)
		low := strings.ToLower(string(trim))
		if strings.HasPrefix(low, "<!doctype html") || strings.HasPrefix(low, "<html") {
			return ".html", true, nil
		}
		if strings.HasPrefix(low, "<?xml") {
			return ".xml", true, nil
		}
		if strings.HasPrefix(low, "{") || strings.HasPrefix(low, "[") {
			// If it's mostly text, call it JSON.
			if isLikelyText(head) {
				return ".json", true, nil
			}
		}
	}

	// Plain text heuristic (no extension implied by content; choose .txt)
	if isLikelyText(head) {
		return ".txt", true, nil
	}

	return "", false, nil
}

func chooseExtDot(originalPath string, overrideExt string, hasOverride bool) (string, string, error) {
	if hasOverride {
		return "." + overrideExt, "override", nil
	}

	detected, ok, err := sniffExtByMagic(originalPath)
	if err != nil {
		return "", "", err
	}
	if ok && detected != "" {
		return detected, "magic", nil
	}

	ext := filepath.Ext(originalPath)
	if ext != "" {
		return ext, "original", nil
	}

	// Fallback for unknown binary content
	return ".bin", "fallback", nil
}

func sidecarPathForTarget(targetAbs string) string {
	// normalized_filename.ext.json
	return targetAbs + ".json"
}

func writeSidecarJSON(jsonPath string, meta sidecarMetadata) error {
	_, err := os.Lstat(jsonPath)
	if err == nil {
		return fmt.Errorf("sidecar already exists: %q", jsonPath)
	}
	if !os.IsNotExist(err) {
		return err
	}

	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	dir := filepath.Dir(jsonPath)
	tmp, err := os.CreateTemp(dir, ".mvv-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	closeOK := false
	defer func() {
		if !closeOK {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	closeOK = true

	return os.Rename(tmpName, jsonPath)
}

func main() {
	var (
		showVersion  bool
		showHelp     bool
		debug        bool
		typeLabel    string
		subTypeLabel string
		extOverride  string
		writeJSON    bool
		repeatType   bool
		repeatAll    bool
	)

	flag.BoolVar(&showHelp, "h", false, "show help")
	flag.BoolVar(&showHelp, "help", false, "show help")

	flag.BoolVar(&showVersion, "v", false, "show version")
	flag.BoolVar(&showVersion, "version", false, "show version")

	flag.BoolVar(&debug, "D", false, "debug / dry-run")
	flag.BoolVar(&debug, "debug", false, "debug / dry-run")

	flag.StringVar(&typeLabel, "type", "", "type label")
	flag.StringVar(&typeLabel, "t", "", "type label")

	flag.StringVar(&subTypeLabel, "stype", "", "subtype label")
	flag.StringVar(&subTypeLabel, "s", "", "subtype label")

	flag.StringVar(&extOverride, "ext", "", "force extension")
	flag.StringVar(&extOverride, "e", "", "force extension")

	flag.BoolVar(&writeJSON, "json", false, "write sidecar JSON")
	flag.BoolVar(&writeJSON, "j", false, "write sidecar JSON")

	flag.BoolVar(&repeatType, "r", false, "reuse last type")
	flag.BoolVar(&repeatAll, "rr", false, "reuse last type, subtype, and extension")

	flag.Usage = usage
	flag.Parse()

	if showHelp {
		usage()
		return
	}

	if showVersion {
		fmt.Printf("%s %s\n", toolName, toolVersion)
		return
	}

	paths := flag.Args()
	if len(paths) == 0 {
		usage()
		os.Exit(1)
	}

	if repeatType && repeatAll {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(os.Stderr, "error: -r and -rr are mutually exclusive")
		os.Exit(2)
	}

	// Apply repeat semantics (nil-safe and explicit).
	if repeatType || repeatAll {
		st, err := loadState()
		if err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		if st == nil || st.TypeLabel == "" {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintln(os.Stderr, "error: no prior state available for -r/-rr")
			os.Exit(2)
		}

		if repeatAll {
			typeLabel = st.TypeLabel
			subTypeLabel = st.SubTypeLabel
			if st.HasExt {
				extOverride = st.Ext
			}
		} else {
			typeLabel = st.TypeLabel
		}
	}

	if typeLabel == "" {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(os.Stderr, "error: --type is required (or use -r / -rr after first run)")
		os.Exit(2)
	}

	if !validLabel(typeLabel) {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(os.Stderr, "error: --type must match [A-Za-z0-9_-]+")
		os.Exit(2)
	}

	if subTypeLabel != "" && !validLabel(subTypeLabel) {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(os.Stderr, "error: --stype must match [A-Za-z0-9_-]+")
		os.Exit(2)
	}

	normalizedExt, hasExt := normalizeExt(extOverride)

	// Persist last-used state so -r/-rr work next time.
	if err := saveState(&lastState{
		TypeLabel:    typeLabel,
		SubTypeLabel: subTypeLabel,
		Ext:          normalizedExt,
		HasExt:       hasExt,
	}); err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(os.Stderr, "error: failed to save state: %v\n", err)
		os.Exit(2)
	}

	hadError := false

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(os.Stderr, "%s: error: %v\n", p, err)
			hadError = true
			continue
		}
		if info.IsDir() {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(os.Stderr, "%s: error: is a directory\n", p)
			hadError = true
			continue
		}

		oldAbs, err := absPath(p)
		if err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(os.Stderr, "%s: error: failed to resolve absolute path: %v\n", p, err)
			hadError = true
			continue
		}

		shaHex, err := fileSHA256Hex(oldAbs)
		if err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(os.Stderr, "%s: error: failed to hash: %v\n", p, err)
			hadError = true
			continue
		}

		extDot, extSrc, err := chooseExtDot(oldAbs, normalizedExt, hasExt)
		if err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(os.Stderr, "%s: error: failed to detect extension: %v\n", p, err)
			hadError = true
			continue
		}

		dirAbs := filepath.Dir(oldAbs)
		newName, prefixLen, err := resolveUniqueName(dirAbs, typeLabel, shaHex, subTypeLabel, extDot)
		if err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(os.Stderr, "%s: error: %v\n", p, err)
			hadError = true
			continue
		}

		newAbs := filepath.Join(dirAbs, newName)

		mode := info.Mode()
		permOctal := fmt.Sprintf("%#o", uint32(mode.Perm()))
		modeStr := mode.String()

		jsonPath := sidecarPathForTarget(newAbs)
		jsonStatus := "off"

		// If the file is already normalized (old == new), treat as a no-op.
		// This avoids "self-collisions" that would otherwise cause the hash prefix to extend.
		if oldAbs == newAbs {
			if debug {
				fmt.Printf("%s -> %s (sha256=%s prefix=%d ext_src=%s mode=%s %s",
					oldAbs, newAbs, shaHex, prefixLen, extSrc, permOctal, modeStr,
				)
				if hasExt {
					fmt.Printf(" ext=%q", normalizedExt)
				}
				if writeJSON {
					fmt.Printf(" json=planned json_path=%q", jsonPath)
				}
				fmt.Println(") (dry-run)")
			} else {
				// In real mode, optionally write JSON sidecar (if requested and not already present).
				if writeJSON {
					meta := sidecarMetadata{
						ToolName:           toolName,
						ToolVersion:        toolVersion,
						TimestampRFC3339:   time.Now().UTC().Format(time.RFC3339Nano),
						OriginalFilename:   filepath.Base(oldAbs),
						OriginalPathAbs:    oldAbs,
						OriginalPermOctal:  permOctal,
						OriginalModeString: modeStr,
					}

					if err := writeSidecarJSON(jsonPath, meta); err != nil {
						//goland:noinspection GoUnhandledErrorResult
						fmt.Fprintf(os.Stderr, "%s: error: failed to write sidecar: %v\n", p, err)
						hadError = true
						jsonStatus = "error"
					} else {
						jsonStatus = "written"
					}
				}

				fmt.Printf("%s -> %s (sha256=%s prefix=%d ext_src=%s mode=%s %s",
					oldAbs, newAbs, shaHex, prefixLen, extSrc, permOctal, modeStr,
				)
				if hasExt {
					fmt.Printf(" ext=%q", normalizedExt)
				}
				if writeJSON {
					fmt.Printf(" json=%s json_path=%q", jsonStatus, jsonPath)
				}
				fmt.Println(") (already normalized)")
			}
			continue
		}

		if debug {
			fmt.Printf("%s -> %s (sha256=%s prefix=%d ext_src=%s mode=%s %s",
				oldAbs, newAbs, shaHex, prefixLen, extSrc, permOctal, modeStr,
			)
			if hasExt {
				fmt.Printf(" ext=%q", normalizedExt)
			}
			if writeJSON {
				fmt.Printf(" json=planned json_path=%q", jsonPath)
			}
			fmt.Println(") (dry-run)")
			continue
		}

		// Real mode: rename.
		if err := os.Rename(oldAbs, newAbs); err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(os.Stderr, "%s: error: rename failed: %v\n", p, err)
			hadError = true
			continue
		}

		if writeJSON {
			meta := sidecarMetadata{
				ToolName:           toolName,
				ToolVersion:        toolVersion,
				TimestampRFC3339:   time.Now().UTC().Format(time.RFC3339Nano),
				OriginalFilename:   filepath.Base(oldAbs),
				OriginalPathAbs:    oldAbs,
				OriginalPermOctal:  permOctal,
				OriginalModeString: modeStr,
			}

			if err := writeSidecarJSON(jsonPath, meta); err != nil {
				// The file has already been renamed at this point.
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintf(os.Stderr, "%s: error: failed to write sidecar: %v\n", p, err)
				hadError = true
				jsonStatus = "error"
			} else {
				jsonStatus = "written"
			}
		}

		fmt.Printf("%s -> %s (sha256=%s prefix=%d ext_src=%s mode=%s %s",
			oldAbs, newAbs, shaHex, prefixLen, extSrc, permOctal, modeStr,
		)
		if hasExt {
			fmt.Printf(" ext=%q", normalizedExt)
		}
		if writeJSON {
			fmt.Printf(" json=%s json_path=%q", jsonStatus, jsonPath)
		}
		fmt.Println(")")
	}

	if hadError {
		os.Exit(2)
	}
}
