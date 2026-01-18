# mvv

`mvv` is a small, single-purpose CLI tool for normalizing malware sample filenames in a deterministic and analyst-friendly way.

It renames files to a structured format based on a user-supplied type label and a SHA-256 hash prefix, with an optional subtype and optional sidecar metadata.

## Filename format

```
type_sha256prefix[_stype].ext
```

- The SHA-256 prefix starts at 8 hex characters and is extended automatically on collision.
- File extensions are chosen in the following order:
  1. `--ext` override (if provided)
  2. Content-based detection (magic)
  3. Original filename extension
  4. Fallback to `.bin`

## Basic usage

Rename a file using a primary type label:

```
mvv -t guloader sample.bin
```

Example result:

```
sample.bin -> guloader_9f3a8c2e.exe
```

## Subtype

Add an optional subtype label:

```
mvv -t oyster -s unpacked payload.dat
```

Result:

```
oyster_1a2b3c4d_unpacked.exe
```

## Dry-run / debug mode

Use `-D` to preview actions without modifying the filesystem:

```
mvv -D -t paypal_scam malicious.pdf
```

## Reusing previous labels

After the first run, reuse the last type label:

```
mvv -r sample1.bin
```

Reuse type, subtype, and extension override:

```
mvv -rr more_samples/*
```

## Sidecar JSON metadata

Write a JSON sidecar next to the renamed file:

```
mvv -t agenttesla -j suspicious.exe
```

This produces:

```
agenttesla_abcdef12.exe
agenttesla_abcdef12.exe.json
```

The sidecar contains tool/version information, original filename and path, original permissions, and a timestamp.

## Notes

- Single command, no subcommands
- No external dependencies
- Persistent state stored in `os.UserConfigDir()`
  (for example: `~/.config/mvv/state.json` on Unix-like systems)

## Future

- Cross-platform (Windows, macOS, Linux)

## License

See the repository for license details.
