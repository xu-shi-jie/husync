# husync

Real-time directory sync tool written in Rust. Watches local directories and automatically syncs changes to a remote host via rsync.

## Features

- Real-time file watching with colored output
- Debounced batch sync
- Initial sync on startup (root files + watched directories)
- Remote sync using rsync with SSH key

## Build

```bash
cargo build --release
```

Binary output:
- Linux/macOS: `target/release/husync`
- Windows: `target/release/husync.exe`

## Usage

```bash
husync data models \
  --remote-user USERNAME \
  --remote-host remote.server.com \
  --remote-base /remote/path \
  --debounce 2.0
```

Show help:

```bash
husync --help
```

## Requirements

- Rust (stable recommended)
- rsync (must be installed)
- SSH access to remote host

## License

MIT. See `LICENSE`.
