package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

const toolName = "mvv"

var toolVersion = "dev"

var inheritNameRE = regexp.MustCompile(
	`^([a-z0-9]{3,}(?:_[a-z0-9]+)*)_((?:[a-f0-9]{2}){4,32})(?:_([a-z0-9]{3,}(?:_[a-z0-9]+)*))?\.[a-z0-9][a-z0-9_-]*$`,
)

type state struct {
	Type       string `json:"type,omitempty"`
	SubType    string `json:"stype,omitempty"`
	Infix      string `json:"infix,omitempty"`
	DestDirAbs string `json:"dest_dir_abs,omitempty"`
	CopyMode   *bool  `json:"copy_mode,omitempty"`
	UnixTime   int64  `json:"unix_time"`
}

type destInfo struct {
	Abs    string
	Source string // "flag" | "state" | "cwd"
}

type sidecarMetadata struct {
	ToolName         string `json:"tool_name"`
	ToolVersion      string `json:"tool_version"`
	TimestampRFC3339 string `json:"timestamp"`
	OriginalFilename string `json:"original_filename"`
	OriginalPathAbs  string `json:"original_path_abs"`
	SHA1             string `json:"sha1"`
	SHA256           string `json:"sha256"`
}

type planData struct {
	DryRun  bool
	Debug   bool
	Mode    string
	Op      string
	WriteJS bool

	Operand     string
	OperandAbs  string
	Dest        destInfo
	DestPersist string

	ExtOverride string
	ExtDot      string

	OldState *state
	Cur      state
	Changed  bool

	ParentEntry  string
	InheritFrom  string
	InheritType  string
	InheritInfix string
	InheritStype string

	PlannedInfix string
	InfixLen     int
	PlannedName  string
	PlannedPath  string

	SHA1Hex   string
	SHA256Hex string

	SidecarPath string
	SidecarJSON []byte
}

func usage(w io.Writer) {
	//goland:noinspection GoUnhandledErrorResult
	fmt.Fprintf(w, `%s — malware sample filename normalizer

Usage:
  %s [options] <file>

Options:
  -h, --help
        Show help and exit

  -v, --version
        Show version and exit

  -d, --dry-run
        Print plan only; do not write state; do not modify disk

  -D, --debug
        Print plan and apply state/sidecar; do not rename/move the file

  -t, --type <label>
        Primary type label

  -s, --stype <label>
        Optional subtype label

  -p
        Enter/refresh parent mode using the operand file (infix computed from file)

  -n <file>
        Enter parent mode by inheriting from an existing filename

  -w, --working <path>
        Destination working directory (stored in state)

  -e, --ext <ext>
        Extension override (accepted; not persisted)

  -j, --json
        Sidecar JSON (accepted; not persisted)

	-x, -xx, -xxx
	      Clear state

	-c
	      Copy for this invocation only (does not persist)

	-cc
	      Toggle persistent copy mode (must be used alone)
`, toolName, toolName)
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

func statePath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfgDir, toolName, "state.json"), nil
}

func loadState() (*state, error) {
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
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("failed to parse state file %q: %w", p, err)
	}
	return &st, nil
}

func writeState(st *state) error {
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

func removeStateFileIfExists() error {
	p, err := statePath()
	if err != nil {
		return err
	}
	err = os.Remove(p)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func absClean(p string) (string, error) {
	a, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(a), nil
}

func resolveDestination(flagDest string, st *state) (destInfo, string, error) {
	// If provided on the command line, always use it and persist it.
	if flagDest != "" {
		d, err := absClean(flagDest)
		if err != nil {
			return destInfo{}, "", err
		}
		return destInfo{Abs: d, Source: "flag"}, d, nil
	}

	// If already stored, use it (do not persist again).
	if st != nil && st.DestDirAbs != "" {
		return destInfo{Abs: st.DestDirAbs, Source: "state"}, "", nil
	}

	// Otherwise, use cwd AND persist it to state.
	cwd, err := os.Getwd()
	if err != nil {
		return destInfo{}, "", err
	}
	cwd, err = absClean(cwd)
	if err != nil {
		return destInfo{}, "", err
	}
	return destInfo{Abs: cwd, Source: "cwd"}, cwd, nil
}

func isDir(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fi.IsDir(), nil
}

func ensureDestDirExists(destAbs string) (bool, error) {
	ok, err := isDir(destAbs)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	return true, nil
}

func targetExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}

	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(dst)
		}
	}()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	ok = true
	return out.Close()
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func normalizeInterspersedArgv(argv []string) []string {
	// Go's standard flag parsing stops at the first non-flag token.
	// This normalizer allows flags anywhere by moving recognized flags
	// (and their values) before positional operands. Honors "--" as end-of-flags.

	expectsValue := map[string]bool{
		"-t": true, "--type": true,
		"-s": true, "--stype": true,
		"-n": true,
		"-w": true, "--working": true,
		"-e": true, "--ext": true,
	}

	boolFlag := map[string]bool{
		"-h": true, "--help": true,
		"-v": true, "--version": true,
		"-d": true, "--dry-run": true,
		"-D": true, "--debug": true,
		"-p": true,
		"-j": true, "--json": true,
		"-x": true, "-xx": true, "-xxx": true,
		"-c": true, "-cc": true,
	}

	var flags []string
	var pos []string

	for i := 0; i < len(argv); i++ {
		a := argv[i]

		if a == "--" {
			pos = append(pos, argv[i+1:]...)
			break
		}

		if len(a) > 1 && a[0] == '-' {
			// Support --key=value / -k=value forms.
			if eq := indexByte(a, '='); eq != -1 {
				key := a[:eq]
				if expectsValue[key] || boolFlag[key] {
					flags = append(flags, a)
					continue
				}
			}

			if expectsValue[a] {
				flags = append(flags, a)
				if i+1 < len(argv) {
					flags = append(flags, argv[i+1])
					i++
				}
				continue
			}

			if boolFlag[a] {
				flags = append(flags, a)
				continue
			}
		}

		// Not a recognized flag token -> positional.
		pos = append(pos, a)
	}

	return append(flags, pos...)
}

func normalizeExtDot(operandPath string, override string) string {
	// Rules:
	//  - if override provided, accept with/without leading dot
	//  - else sniff by content first
	//  - else fall back to the existing extension (if any)
	//  - else fallback .bin
	if override != "" {
		o := strings.TrimSpace(override)
		o = strings.TrimPrefix(o, ".")
		if o == "" {
			return ".bin"
		}
		return "." + o
	}

	if sniffed, ok, err := sniffExtByMagic(operandPath); err == nil && ok && sniffed != "" {
		return sniffed
	}

	ext := filepath.Ext(operandPath)
	if ext != "" {
		return ext
	}

	return ".bin"
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

func fileSHA1Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum), nil
}

func plannedStem(typeLabel, infix, stype string) string {
	if stype != "" {
		return fmt.Sprintf("%s_%s_%s", typeLabel, infix, stype)
	}
	return fmt.Sprintf("%s_%s", typeLabel, infix)
}

func resolveUniqueInfixWithWarning(destDir, typeLabel, stype, extDot, shaHex string, warn io.Writer) (string, int, error) {
	// Start at 8 hex chars; on collision extend by 2.
	prefixLen := 8
	for {
		if prefixLen > len(shaHex) {
			return "", 0, fmt.Errorf("internal error: sha256 length unexpected")
		}
		infix := shaHex[:prefixLen]
		name := plannedStem(typeLabel, infix, stype) + extDot
		target := filepath.Join(destDir, name)

		_, err := os.Lstat(target)
		if err == nil {
			// Collision.
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(warn, "warning: collision for %q; extending sha256 prefix\n", target)

			if prefixLen >= 64 {
				return "", 0, fmt.Errorf("unable to find unique name (sha256 prefix exhausted)")
			}
			prefixLen += 2
			continue
		}
		if os.IsNotExist(err) {
			return infix, prefixLen, nil
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

	// PE (MZ) -> .exe vs .dll
	if len(head) >= 2 && head[0] == 'M' && head[1] == 'Z' {
		// Minimal PE parsing:
		// DOS header e_lfanew at 0x3C (little endian uint32)
		if len(head) >= 0x40 {
			eLFANew := int(binary.LittleEndian.Uint32(head[0x3C:0x40]))
			// Need: "PE\0\0" (4) + IMAGE_FILE_HEADER (20)
			if eLFANew >= 0 && eLFANew+4+20 <= len(head) {
				sig := head[eLFANew : eLFANew+4]
				//goland:noinspection GrazieInspection
				if bytes.Equal(sig, []byte{'P', 'E', 0x00, 0x00}) {
					// Characteristics is uint16 at offset 18 within IMAGE_FILE_HEADER
					// IMAGE_FILE_HEADER starts immediately after signature.
					fh := head[eLFANew+4 : eLFANew+4+20]
					characteristics := binary.LittleEndian.Uint16(fh[18:20])
					const imageFileDLL = 0x2000
					if characteristics&imageFileDLL != 0 {
						return ".dll", true, nil
					}
				}
			}
		}
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
		return ".cfbf", true, nil
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
		// Cap work to avoid large allocations / surprises.
		const maxLowerScan = 128
		lowSrc := trim
		if len(lowSrc) > maxLowerScan {
			lowSrc = lowSrc[:maxLowerScan]
		}
		low := strings.ToLower(string(lowSrc))

		if strings.HasPrefix(low, "<!doctype html") || strings.HasPrefix(low, "<html") {
			return ".html", true, nil
		}
		if strings.HasPrefix(low, "<?xml") {
			return ".xml", true, nil
		}
		if strings.HasPrefix(low, "{") || strings.HasPrefix(low, "[") {
			// If it's mostly text, call it JSON.
			// Additional guard: reject NUL-containing data (common in binaries).
			if isLikelyText(head) && bytes.IndexByte(head, 0x00) == -1 {
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

func sidecarPathFor(plannedPath string) string {
	return plannedPath + ".json"
}

func buildSidecarJSON(opAbs string, sha1Hex string, sha256Hex string) ([]byte, error) {
	sc := sidecarMetadata{
		ToolName:         toolName,
		ToolVersion:      toolVersion,
		TimestampRFC3339: time.Now().UTC().Format(time.RFC3339),
		OriginalFilename: filepath.Base(opAbs),
		OriginalPathAbs:  opAbs,
		SHA1:             sha1Hex,
		SHA256:           sha256Hex,
	}

	b, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	return b, nil
}

func mustMarshalIndentStateForDisplay(st state) []byte {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		// This should never happen; keep output deterministic if it does.
		return []byte("{}\n")
	}
	b = append(b, '\n')
	return b
}

//goland:noinspection GoUnhandledErrorResult
func printPlan(
	w io.Writer,
	opAbs string,
	dest destInfo,
	mode string,
	operation string,
	st state,
	plannedInfix string,
	infixLen int,
	shaHex string,
	plannedName string,
	plannedPath string,
	parentEntry string,
	inheritFrom string,
	inheritType string,
	inheritInfix string,
	inheritStype string,
	extOverride string,
	writeJSON bool,
	sidecarPath string,
) {
	fmt.Fprintln(w, "PLAN")
	fmt.Fprintf(w, "  file:          %q\n", opAbs)
	fmt.Fprintf(w, "  destination:   %q\n", dest.Abs)
	fmt.Fprintf(w, "  dest_source:   %s\n", dest.Source)
	fmt.Fprintf(w, "  mode:          %s\n", mode)
	fmt.Fprintf(w, "  operation:     %s\n", operation)
	fmt.Fprintf(w, "  type:          %q\n", st.Type)
	fmt.Fprintf(w, "  stype:         %q\n", st.SubType)
	fmt.Fprintf(w, "  infix:         %q\n", plannedInfix)
	fmt.Fprintf(w, "  infix_len:     %d\n", infixLen)
	fmt.Fprintf(w, "  sha256:        %q\n", shaHex)
	fmt.Fprintf(w, "  planned_name:  %q\n", plannedName)
	fmt.Fprintf(w, "  planned_path:  %q\n", plannedPath)
	fmt.Fprintf(w, "  parent_entry:  %s\n", parentEntry)
	fmt.Fprintf(w, "  inherit_from:  %q\n", inheritFrom)
	fmt.Fprintf(w, "  inherit_type:  %q\n", inheritType)
	fmt.Fprintf(w, "  inherit_infix: %q\n", inheritInfix)
	fmt.Fprintf(w, "  inherit_stype: %q\n", inheritStype)
	fmt.Fprintf(w, "  ext_override:  %q\n", extOverride)
	fmt.Fprintf(w, "  json:          %t\n", writeJSON)
	if writeJSON {
		fmt.Fprintf(w, "  sidecar_path:  %q\n", sidecarPath)
	}
}

type parsedFlags struct {
	ShowHelp    bool
	ShowVersion bool

	PrintState bool

	DryRun bool
	Debug  bool

	TypeLabel string
	Stype     string

	EnterParentByOperand bool
	InheritFrom          string

	DestFlag string

	ExtOverride string
	WriteJSON   bool

	CopyOnce       bool
	ToggleCopyMode bool

	Clear1 bool
	Clear2 bool
	Clear3 bool
}

func parseFlags(argv []string, stderr io.Writer) (parsedFlags, *flag.FlagSet, int) {
	var pf parsedFlags

	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }

	fs.BoolVar(&pf.ShowHelp, "h", false, "show help")
	fs.BoolVar(&pf.ShowHelp, "help", false, "show help")
	fs.BoolVar(&pf.ShowVersion, "v", false, "show version")
	fs.BoolVar(&pf.ShowVersion, "version", false, "show version")

	fs.BoolVar(&pf.PrintState, "P", false, "print persistent state and exit")
	fs.BoolVar(&pf.PrintState, "print", false, "print persistent state and exit")

	fs.BoolVar(&pf.DryRun, "d", false, "dry run (no state write, no disk changes)")
	fs.BoolVar(&pf.DryRun, "dry-run", false, "dry run (no state write, no disk changes)")
	fs.BoolVar(&pf.Debug, "D", false, "debug mode (state write, no disk changes)")
	fs.BoolVar(&pf.Debug, "debug", false, "debug mode (state write, no disk changes)")

	fs.StringVar(&pf.TypeLabel, "t", "", "type label")
	fs.StringVar(&pf.TypeLabel, "type", "", "type label")
	fs.StringVar(&pf.Stype, "s", "", "subtype label")
	fs.StringVar(&pf.Stype, "stype", "", "subtype label")

	fs.BoolVar(&pf.EnterParentByOperand, "p", false, "enter parent mode using operand")
	fs.StringVar(&pf.InheritFrom, "n", "", "inherit parent mode from existing file")

	fs.StringVar(&pf.DestFlag, "w", "", "working directory")
	fs.StringVar(&pf.DestFlag, "working", "", "working directory")

	fs.StringVar(&pf.ExtOverride, "e", "", "extension override (accepted; not persisted)")
	fs.StringVar(&pf.ExtOverride, "ext", "", "extension override (accepted; not persisted)")
	fs.BoolVar(&pf.WriteJSON, "j", false, "sidecar JSON (accepted; not persisted)")
	fs.BoolVar(&pf.WriteJSON, "json", false, "sidecar JSON (accepted; not persisted)")

	fs.BoolVar(&pf.Clear1, "x", false, "clear infix")
	fs.BoolVar(&pf.Clear2, "xx", false, "clear infix/type/stype")
	fs.BoolVar(&pf.Clear3, "xxx", false, "clear infix/type/stype/destination")

	fs.BoolVar(&pf.CopyOnce, "c", false, "copy for this invocation only (does not persist)")
	fs.BoolVar(&pf.ToggleCopyMode, "cc", false, "toggle persistent copy mode (must be used alone)")

	argv = normalizeInterspersedArgv(argv)

	if err := fs.Parse(argv); err != nil {
		return parsedFlags{}, fs, 2
	}

	// Normalize user-provided labels/ext early (before validation/state).
	pf.TypeLabel = strings.ToLower(pf.TypeLabel)
	pf.Stype = strings.ToLower(pf.Stype)
	pf.ExtOverride = strings.ToLower(pf.ExtOverride)

	return pf, fs, 0
}

func runClear(pf parsedFlags, fs *flag.FlagSet, stdout, stderr io.Writer) int {
	allowStateWrite := !pf.DryRun // default and --debug allow state writes; --dry-run forbids them

	if !allowStateWrite {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: --dry-run/-d cannot be used with -x/-xx/-xxx (would modify state)")
		return 2
	}

	n := 0
	if pf.Clear1 {
		n++
	}
	if pf.Clear2 {
		n++
	}
	if pf.Clear3 {
		n++
	}
	if n != 1 {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: exactly one of -x, -xx, -xxx must be specified")
		return 2
	}

	if pf.TypeLabel != "" || pf.Stype != "" || pf.EnterParentByOperand || pf.InheritFrom != "" || pf.DestFlag != "" || pf.ExtOverride != "" ||
		pf.WriteJSON || pf.DryRun || pf.Debug || pf.CopyOnce || pf.ToggleCopyMode {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: -x/-xx/-xxx cannot be combined with other options")
		return 2
	}

	if len(fs.Args()) != 0 {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: -x/-xx/-xxx do not accept operands")
		return 2
	}

	st, err := loadState()
	if err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if st == nil {
		st = &state{}
	}

	switch {
	case pf.Clear1:
		st.Infix = ""
	case pf.Clear2:
		st.Infix = ""
		st.Type = ""
		st.SubType = ""
	case pf.Clear3:
		st.Infix = ""
		st.Type = ""
		st.SubType = ""
		st.DestDirAbs = ""
	}

	copyOff := st.CopyMode == nil || !*st.CopyMode
	if st.Type == "" && st.SubType == "" && st.Infix == "" && st.DestDirAbs == "" && copyOff {
		if err := removeStateFileIfExists(); err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: failed to clear state: %v\n", err)
			return 2
		}
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stdout, "STATE cleared")
		return 0
	}

	if err := writeState(st); err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: failed to write state: %v\n", err)
		return 2
	}
	//goland:noinspection GoUnhandledErrorResult
	fmt.Fprintln(stdout, "STATE updated")
	return 0
}

func runToggleCopyMode(pf parsedFlags, fs *flag.FlagSet, stdout, stderr io.Writer) int {
	allowStateWrite := !pf.DryRun // default and --debug allow state writes; --dry-run forbids them

	if !allowStateWrite {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: --dry-run/-d cannot be used with -cc (would modify state)")
		return 2
	}

	if pf.ShowHelp || pf.ShowVersion || pf.PrintState || pf.Debug || pf.CopyOnce || pf.Clear1 || pf.Clear2 || pf.Clear3 ||
		pf.TypeLabel != "" || pf.Stype != "" || pf.EnterParentByOperand || pf.InheritFrom != "" || pf.DestFlag != "" ||
		pf.ExtOverride != "" || pf.WriteJSON {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: -cc must be used alone")
		return 2
	}

	if len(fs.Args()) != 0 {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: -cc does not accept operands")
		return 2
	}

	st, err := loadState()
	if err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	if st == nil {
		st = &state{}
	}

	cur := false
	if st.CopyMode != nil {
		cur = *st.CopyMode
	}
	next := !cur
	st.CopyMode = &next

	// If toggling produces a fully empty state with copy_mode off, remove the file.
	if st.Type == "" && st.SubType == "" && st.Infix == "" && st.DestDirAbs == "" && !next {
		if err := removeStateFileIfExists(); err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: failed to update state: %v\n", err)
			return 2
		}
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stdout, "STATE cleared")
		return 0
	}

	if err := writeState(st); err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: failed to write state: %v\n", err)
		return 2
	}

	//goland:noinspection GoUnhandledErrorResult
	fmt.Fprintln(stdout, "STATE updated")
	return 0
}

func isWorkingOnlyCommand(pf parsedFlags, fs *flag.FlagSet) bool {
	// Allow: just -w/--working (and optional -d/-D), with no operands.
	if len(fs.Args()) != 0 {
		return false
	}
	if pf.DestFlag == "" {
		return false
	}
	if pf.TypeLabel != "" || pf.Stype != "" || pf.EnterParentByOperand || pf.InheritFrom != "" || pf.ExtOverride != "" || pf.WriteJSON ||
		pf.CopyOnce || pf.ToggleCopyMode {
		return false
	}
	// Clear flags handled elsewhere; help/version handled earlier.
	return true
}

func runSetWorkingOnly(pf parsedFlags, stdout, stderr io.Writer) int {
	if pf.DryRun && pf.Debug {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: --dry-run/-d and --debug/-D are mutually exclusive")
		return 2
	}

	allowStateWrite := !pf.DryRun // default and --debug allow state writes; --dry-run forbids them

	oldState, err := loadState()
	if err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	var cur state
	if oldState != nil {
		cur = *oldState
	}

	// Resolve destination and persist it (this always returns destToPersist for -w).
	_, destToPersist, err := resolveDestination(pf.DestFlag, oldState)
	if err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: failed to resolve destination: %v\n", err)
		return 2
	}
	if destToPersist != "" {
		cur.DestDirAbs = destToPersist
	}

	// Compare ignoring unix_time for stable decision.
	var oldComparable state
	if oldState != nil {
		oldComparable = *oldState
	}
	oldComparable.UnixTime = 0
	newComparable := cur
	newComparable.UnixTime = 0

	if reflect.DeepEqual(oldComparable, newComparable) {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stdout, "STATE unchanged")
		return 0
	}

	if !allowStateWrite {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stdout, "STATE would update")
		return 0
	}

	if err := writeState(&cur); err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: failed to write state: %v\n", err)
		return 2
	}

	//goland:noinspection GoUnhandledErrorResult
	fmt.Fprintln(stdout, "STATE updated")
	return 0
}

func phasePlanValidate(pf parsedFlags, fs *flag.FlagSet, stderr io.Writer) (*planData, int) {
	if pf.DryRun && pf.Debug {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: --dry-run/-d and --debug/-D are mutually exclusive")
		return nil, 2
	}

	allowStateWrite := !pf.DryRun // default and --debug allow state writes; --dry-run forbids them

	// Operational commands require exactly one operand.
	args := fs.Args()
	if len(args) != 1 {
		usage(stderr)
		return nil, 2
	}
	operand := args[0]

	if pf.EnterParentByOperand && pf.InheritFrom != "" {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: -p and -n are mutually exclusive")
		return nil, 2
	}

	// Validate operand is not a directory.
	if d, err := isDir(operand); err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: %v\n", err)
		return nil, 2
	} else if d {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: operand is a directory")
		return nil, 2
	}

	// Validate -n argument (exists and file).
	if pf.InheritFrom != "" {
		if d, err := isDir(pf.InheritFrom); err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: -n: %v\n", err)
			return nil, 2
		} else if d {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintln(stderr, "error: -n must reference a file, not a directory")
			return nil, 2
		}
	}

	// Validate labels if provided.
	if pf.TypeLabel != "" && !validLabel(pf.TypeLabel) {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: --type must match [A-Za-z0-9_-]+")
		return nil, 2
	}
	if pf.Stype != "" && !validLabel(pf.Stype) {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: --stype must match [A-Za-z0-9_-]+")
		return nil, 2
	}

	// Load state.
	oldState, err := loadState()
	if err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: %v\n", err)
		return nil, 2
	}

	var cur state
	if oldState != nil {
		cur = *oldState
	}

	stateCopyOn := cur.CopyMode != nil && *cur.CopyMode
	opStr := "move"
	if pf.CopyOnce || stateCopyOn {
		opStr = "copy"
	}

	// State invariant: infix is present but type missing -> invalid state.
	if cur.Infix != "" && cur.Type == "" {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: state invalid; clear with -xx or -xxx")
		return nil, 2
	}

	// Resolve destination (and possibly persist it).
	dest, destToPersist, err := resolveDestination(pf.DestFlag, oldState)
	if err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: failed to resolve destination: %v\n", err)
		return nil, 2
	}

	if allowStateWrite && destToPersist != "" {
		cur.DestDirAbs = destToPersist
	} else if !allowStateWrite && dest.Source == "cwd" {
		// If dry-run and dest came from cwd (which normally would be persisted),
		// do not mutate cur.DestDirAbs.
		destToPersist = ""
	}

	changed := false
	parentEntry := "none"

	inheritType := ""
	inheritInfix := ""
	inheritStype := ""

	switch {
	case pf.InheritFrom != "":
		// Enter parent mode by inheritance (regex over base name).
		if pf.TypeLabel != "" {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintln(stderr, "error: conflicting source of type provided with -n")
			return nil, 2
		}

		base := filepath.Base(pf.InheritFrom)
		m := inheritNameRE.FindStringSubmatch(base)
		if m == nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintln(stderr, "error: filename pattern not recognized")
			return nil, 2
		}
		// m[1]=type, m[2]=infix, m[3]=optional stype (can be empty).
		inheritType = m[1]
		inheritInfix = m[2]
		inheritStype = m[3]

		cur.Type = inheritType
		cur.Infix = inheritInfix
		if pf.Stype != "" {
			cur.SubType = pf.Stype
		} else {
			cur.SubType = inheritStype
		}

		parentEntry = "n"
		changed = true

	case pf.EnterParentByOperand:
		// Enter/refresh parent mode by computing infix from the operand file.
		// Special case: if -t not provided, use existing state.type/stype.
		if pf.TypeLabel != "" {
			cur.Type = pf.TypeLabel
			if pf.Stype != "" {
				cur.SubType = pf.Stype
			} else {
				cur.SubType = ""
			}
		} else {
			if cur.Type == "" {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(stderr, "error: no state exists; type required")
				return nil, 2
			}
			if pf.Stype != "" {
				cur.SubType = pf.Stype
			}
		}
		parentEntry = "p"
		changed = true

	default:
		if cur.Infix != "" {
			// Parent mode continuation.
			if pf.TypeLabel != "" {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(stderr, "error: type not allowed in parent mode")
				return nil, 2
			}
			if pf.Stype != "" {
				cur.SubType = pf.Stype
				changed = true
			}
		} else {
			// Base mode behavior.
			if pf.TypeLabel != "" {
				cur.Type = pf.TypeLabel
				if pf.Stype != "" {
					cur.SubType = pf.Stype
				} else {
					cur.SubType = ""
				}
				changed = true
			} else if pf.Stype != "" {
				if cur.Type == "" {
					//goland:noinspection GoUnhandledErrorResult
					fmt.Fprintln(stderr, "error: no state exists; type required")
					return nil, 2
				}
				cur.SubType = pf.Stype
				changed = true
			} else {
				if cur.Type == "" {
					//goland:noinspection GoUnhandledErrorResult
					fmt.Fprintln(stderr, "error: no state exists; type required")
					return nil, 2
				}
			}
		}
	}

	// Compute hashes + planned name/path.
	opAbs, err := absClean(operand)
	if err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: failed to resolve operand: %v\n", err)
		return nil, 2
	}

	sha256Hex, err := fileSHA256Hex(opAbs)
	if err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: failed to hash file (sha256): %v\n", err)
		return nil, 2
	}

	sha1Hex, err := fileSHA1Hex(opAbs)
	if err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: failed to hash file (sha1): %v\n", err)
		return nil, 2
	}

	extDot := normalizeExtDot(opAbs, pf.ExtOverride)

	mode := "base"
	var plannedInfix string
	var infixLen int

	if parentEntry == "p" {
		// -p explicitly enters/refreshes parent mode: compute and STORE infix.
		infix, prefixLen, err := resolveUniqueInfixWithWarning(dest.Abs, cur.Type, cur.SubType, extDot, sha256Hex, stderr)
		if err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: failed to resolve unique infix: %v\n", err)
			return nil, 2
		}

		if allowStateWrite {
			cur.Infix = infix
			changed = true
		}

		plannedInfix = infix
		infixLen = prefixLen
		mode = "parent"
	} else if cur.Infix != "" {
		// Already in parent mode (or inherited -n): use state infix.
		mode = "parent"
		plannedInfix = cur.Infix
		infixLen = len(cur.Infix)
	} else {
		// Base mode: compute infix but do NOT store.
		infix, prefixLen, err := resolveUniqueInfixWithWarning(dest.Abs, cur.Type, cur.SubType, extDot, sha256Hex, stderr)
		if err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: failed to resolve unique infix: %v\n", err)
			return nil, 2
		}
		plannedInfix = infix
		infixLen = prefixLen
	}

	plannedName := plannedStem(cur.Type, plannedInfix, cur.SubType) + extDot
	plannedPath := filepath.Join(dest.Abs, plannedName)

	// Parent-mode collisions should be errors (no infix extension in parent mode).
	// Includes -n (inherited) and continuation (parentEntry=none).
	parentCollisionMustError := mode == "parent" && parentEntry != "p" && cur.Infix != ""

	// In default mode (no -d and no -D), we must not clobber an existing target.
	// For base / -p, the infix-extension loop should prevent this by construction, but we still check
	// to surface races and keep behavior consistent across modes.
	plannedTargetMustBeFree := !pf.DryRun && !pf.Debug

	if parentCollisionMustError || plannedTargetMustBeFree {
		exists, err := targetExists(plannedPath)
		if err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: failed to check target: %v\n", err)
			return nil, 2
		}
		if exists {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: file already exists: %q\n", plannedPath)
			return nil, 2
		}
	}

	// Sidecar planning / existence check (for all modes).
	var scPath string
	var scBytes []byte
	if pf.WriteJSON {
		scPath = sidecarPathFor(plannedPath)

		exists, err := targetExists(scPath)
		if err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: failed to check sidecar: %v\n", err)
			return nil, 2
		}
		if exists {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: sidecar already exists: %q\n", scPath)
			return nil, 2

		}

		b, err := buildSidecarJSON(opAbs, sha1Hex, sha256Hex)
		if err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: failed to build sidecar JSON: %v\n", err)
			return nil, 2
		}
		scBytes = b
	}

	pd := &planData{
		DryRun:  pf.DryRun,
		Debug:   pf.Debug,
		Mode:    mode,
		Op:      opStr,
		WriteJS: pf.WriteJSON,

		Operand:     operand,
		OperandAbs:  opAbs,
		Dest:        dest,
		DestPersist: destToPersist,

		ExtOverride: pf.ExtOverride,
		ExtDot:      extDot,

		OldState: oldState,
		Cur:      cur,
		Changed:  changed,

		ParentEntry:  parentEntry,
		InheritFrom:  pf.InheritFrom,
		InheritType:  inheritType,
		InheritInfix: inheritInfix,
		InheritStype: inheritStype,

		PlannedInfix: plannedInfix,
		InfixLen:     infixLen,
		PlannedName:  plannedName,
		PlannedPath:  plannedPath,

		SHA1Hex:   sha1Hex,
		SHA256Hex: sha256Hex,

		SidecarPath: scPath,
		SidecarJSON: scBytes,
	}

	return pd, 0
}

func phasePersistState(pd *planData, stderr io.Writer) int {
	allowStateWrite := !pd.DryRun // default and --debug allow state writes; --dry-run forbids them
	if !allowStateWrite {
		return 0
	}

	changed := pd.Changed
	if !changed && pd.DestPersist != "" {
		changed = true
	}

	if !changed {
		return 0
	}

	var oldComparable state
	if pd.OldState != nil {
		oldComparable = *pd.OldState
	}
	oldComparable.UnixTime = 0
	newComparable := pd.Cur
	newComparable.UnixTime = 0

	if reflect.DeepEqual(oldComparable, newComparable) {
		return 0
	}

	if err := writeState(&pd.Cur); err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: failed to write state: %v\n", err)
		return 2
	}

	return 0
}

func wouldWriteStateIfNotDryRun(pd *planData) bool {
	changed := pd.Changed
	if !changed && pd.DestPersist != "" {
		changed = true
	}
	if !changed {
		return false
	}

	var oldComparable state
	if pd.OldState != nil {
		oldComparable = *pd.OldState
	}
	oldComparable.UnixTime = 0
	newComparable := pd.Cur
	newComparable.UnixTime = 0

	return !reflect.DeepEqual(oldComparable, newComparable)
}

func printDryRunStateBeforeAfter(pd *planData, stdout io.Writer) error {
	// BEFORE: exactly as it exists on disk (or {} if missing).
	var before state
	if pd.OldState != nil {
		before = *pd.OldState
	} else {
		before = state{}
	}

	// AFTER: what would be written by this invocation (including updated unix_time if it changes).
	after := pd.Cur
	if wouldWriteStateIfNotDryRun(pd) {
		after.UnixTime = time.Now().Unix()
	}

	//goland:noinspection GoUnhandledErrorResult
	fmt.Fprintln(stdout, "STATE BEFORE")
	if _, err := stdout.Write(mustMarshalIndentStateForDisplay(before)); err != nil {
		return err
	}

	//goland:noinspection GoUnhandledErrorResult
	fmt.Fprintln(stdout, "STATE AFTER")
	_, err := stdout.Write(mustMarshalIndentStateForDisplay(after))
	return err
}

func phaseRenameIfNeeded(pd *planData, stderr io.Writer) int {
	// Default (no -d and no -D): perform the rename/move as the final step.
	if pd.DryRun || pd.Debug {
		return 0
	}

	// Require destination to exist and be a directory (consistent with sidecar checks).
	ok, err := ensureDestDirExists(pd.Dest.Abs)
	if err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: failed to stat destination: %v\n", err)
		return 2
	}
	if !ok {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintln(stderr, "error: destination is not a directory")
		return 2
	}

	// Safety: do not clobber an existing target.
	exists, err := targetExists(pd.PlannedPath)
	if err != nil {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: failed to check target: %v\n", err)
		return 2
	}
	if exists {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: file already exists: %q\n", pd.PlannedPath)
		return 2

	}
	if pd.Op == "copy" {
		if err := copyFile(pd.OperandAbs, pd.PlannedPath); err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: copy failed: %v\n", err)
			return 2
		}
		return 0
	}

	if err := os.Rename(pd.OperandAbs, pd.PlannedPath); err != nil {
		// Cross-device moves surface here (no copy+delete yet).
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stderr, "error: rename failed: %v\n", err)
		return 2
	}

	return 0
}

func phaseSidecarAndOutput(pd *planData, stdout, stderr io.Writer) int {
	// Print PLAN only for -d (dry-run) and -D (debug).
	if pd.DryRun || pd.Debug {
		printPlan(
			stdout,
			pd.OperandAbs,
			pd.Dest,
			pd.Mode,
			pd.Op,
			pd.Cur,
			pd.PlannedInfix,
			pd.InfixLen,
			pd.SHA256Hex,
			pd.PlannedName,
			pd.PlannedPath,
			pd.ParentEntry,
			pd.InheritFrom,
			pd.InheritType,
			pd.InheritInfix,
			pd.InheritStype,
			pd.ExtOverride,
			pd.WriteJS,
			pd.SidecarPath,
		)
	}

	// In --dry-run only, show state before/after without writing.
	if pd.DryRun {
		if err := printDryRunStateBeforeAfter(pd, stdout); err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: failed to write dry-run state output: %v\n", err)
			return 2
		}
	}

	// Sidecar action:
	//  - dry-run: print sidecar JSON after the plan (and after STATE BEFORE/AFTER)
	//  - debug or default: write sidecar JSON to disk
	if pd.WriteJS {
		if pd.DryRun {
			// Print the sidecar JSON verbatim after the plan.
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintln(stdout)
			if _, err := stdout.Write(pd.SidecarJSON); err != nil {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintf(stderr, "error: failed to write sidecar to stdout: %v\n", err)
				return 2
			}
		} else {
			// Do not create destination directories here; require destination to exist.
			ok, err := ensureDestDirExists(pd.Dest.Abs)
			if err != nil {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintf(stderr, "error: failed to stat destination: %v\n", err)
				return 2
			} else if !ok {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(stderr, "error: destination is not a directory")
				return 2
			}

			if err := os.WriteFile(pd.SidecarPath, pd.SidecarJSON, 0o600); err != nil {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintf(stderr, "error: failed to write sidecar: %v\n", err)
				return 2
			}
		}
	}

	// Final step in default mode: rename/move the operand into the planned path.
	return phaseRenameIfNeeded(pd, stderr)
}

func run(argv []string, stdout, stderr io.Writer) int {
	pf, fs, rc := parseFlags(argv, stderr)
	if rc != 0 {
		return rc
	}

	if pf.ShowHelp {
		usage(stdout)
		return 0
	}
	if pf.ShowVersion {
		//goland:noinspection GoUnhandledErrorResult
		fmt.Fprintf(stdout, "%s %s\n", toolName, toolVersion)
		return 0
	}

	if pf.PrintState {
		p, err := statePath()
		if err != nil {
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		b, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				//goland:noinspection GoUnhandledErrorResult
				fmt.Fprintln(stdout, "STATE does not exist")
				return 0
			}
			//goland:noinspection GoUnhandledErrorResult
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		//goland:noinspection GoUnhandledErrorResult
		stdout.Write(b)
		return 0
	}

	// Clear flags are exclusive and operand-less.
	if pf.Clear1 || pf.Clear2 || pf.Clear3 {
		return runClear(pf, fs, stdout, stderr)
	}

	// Toggle persistent copy mode (exclusive and operand-less).
	if pf.ToggleCopyMode {
		return runToggleCopyMode(pf, fs, stdout, stderr)
	}

	// Allow setting working directory with no operand.
	if isWorkingOnlyCommand(pf, fs) {
		return runSetWorkingOnly(pf, stdout, stderr)
	}

	pd, rc := phasePlanValidate(pf, fs, stderr)
	if rc != 0 {
		return rc
	}

	rc = phasePersistState(pd, stderr)
	if rc != 0 {
		return rc
	}

	return phaseSidecarAndOutput(pd, stdout, stderr)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
