# mvv

`mvv` is a single‑purpose CLI tool for normalizing malware sample filenames in a deterministic, analyst‑friendly way.
It is designed for day‑to‑day reverse‑engineering and malware triage workflows where consistent naming, collision safety, and reproducibility matter.

The tool renames (or moves) a file to a structured name derived from analyst‑supplied labels and cryptographic hashes, with optional persistent state and optional JSON sidecar metadata.

---

## Filename format

```
<type>_<hash-infix>[_<stype>].<ext>
```

- **type**: primary analyst label (required initially)
- **hash‑infix**: SHA‑256 infix, starting at 8 hex characters and automatically extended on collision
- **stype**: optional subtype label
- **ext**: resolved extension

### Extension resolution order

1. `--ext / -e` override (if provided)
2. Content‑based magic sniffing
3. Original filename extension
4. Fallback to `.bin`

---

## Basic usage

Rename a file using a primary type label:

```bash
mvv -t guloader sample.bin
```

Result:

```text
sample.bin → guloader_9f3a8c2e.exe
```

---

## Subtype labels

Add an optional subtype:

```bash
mvv -t oyster -s unpacked payload.dat
```

Result:

```text
oyster_1a2b3c4d_unpacked.exe
```

---

## Working directory

By default, files are renamed in the current directory.
You can set a persistent working directory:

```bash
mvv -w ~/samples
```

This updates state only and performs no rename.

---

## Parent mode

Parent mode allows multiple related samples to share a common hash infix.

### Enter parent mode using a file

```bash
mvv -t agenttesla -p first_sample.bin
```

The computed hash infix is stored in state.

### Continue parent mode

Subsequent runs reuse the stored infix:

```bash
mvv second_sample.bin
```

### Inherit parent mode from an existing filename

```bash
mvv -n agenttesla_abcdef12.exe other_sample.bin
```

---


## Copy mode

Copy mode controls whether file operations are performed as **move** or **copy**.

- Default behavior is **move**.
- `-c` switches the **current invocation only** from move to copy.
  - This modifier does not affect the persistent state.
- `-cc` toggles the persistent mode between move and copy.
  - Must be used alone, with no other switches or operands.

When `--dry-run` or `--debug (-D)` is used, the PLAN will show the selected operation explicitly as
`operation: move` or `operation: copy`.

Persistent state includes an optional `copy_mode` flag. If missing or false, move mode is assumed.

## Collision behavior

- **Base mode and `-p`**:
  Hash infix is automatically extended by 2 hex characters until a unique filename is found.

- **Parent continuation / `-n`**:
  Collisions are **hard errors**. The infix is never extended.

- **Default execution**:
  The final target must not already exist. Any collision results in an error.

---

## Dry‑run and debug modes

### Dry‑run (`-d`)

```bash
mvv -d -t paypal_scam invoice.pdf
```

- Prints the full execution plan
- Prints **STATE BEFORE** and **STATE AFTER**
- Prints sidecar JSON to stdout (if `-j`)
- Does **not** write state, sidecar, or rename files

### Debug (`-D`)

```bash
mvv -D -t paypal_scam invoice.pdf
```

- Prints the execution plan
- Writes state and sidecar JSON
- Does **not** rename or move the file

### Default (no flag)

- Writes state
- Writes sidecar JSON (if `-j`)
- Renames or moves the file

---

## Sidecar JSON (`-j`)

```bash
mvv -t agenttesla -j suspicious.exe
```

Creates:

```text
agenttesla_abcdef12.exe
agenttesla_abcdef12.exe.json
```

### Sidecar contents

```json
{
  "tool_name": "mvv",
  "tool_version": "…",
  "timestamp": "RFC3339",
  "original_filename": "...",
  "original_path_abs": "...",
  "sha1": "...",
  "sha256": "..."
}
```

If the sidecar already exists, execution halts with an error.

---

## Persistent state

State is stored under:

- macOS: `~/Library/Application Support/mvv/state.json`
- Linux: `~/.config/mvv/state.json`
- Windows: `%AppData%\mvv\state.json`

Stored fields include:

- last used type / subtype
- parent hash infix (if any)
- working directory

State can be cleared using:

```bash
-x     clear infix
-xx    clear infix, type, subtype
-xxx   clear infix, type, subtype, destination
```

State can be printed using:

```bash
mvv -P
```


---

## List destination directory (`-l` / `--list`)

Prints a long-format directory listing of the persisted working directory (`dest_dir_abs` in state).

Rules:

- Must be used **alone**
- Accepts **no operands**
- Reads state only (no writes)
- If state is missing or no destination is set, prints a clear message

Example:

```bash
mvv -l
```


---

## Properties

- Single command, no subcommands
- Standard library only
- Cross‑platform (Windows, macOS, Linux)
- Deterministic, collision‑safe behavior

---

## License

See the repository for license details.
