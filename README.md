# Foundry LowkeyCast

This repo contains the custom LowkeyCast helper used with Foundry. It adds the `lk` command to your Foundry install so you can audit contracts faster from any device.

## What it includes

- a custom `lk` launcher
- the python-based LowkeyCast logic
- an installer that copies the changes into your local Foundry installation

## Install on any device

Run this directly from a fresh machine:

```bash
curl -fsSL https://raw.githubusercontent.com/Toji254/foundry-lowkey/main/install.sh | bash
```

This will:

- create `~/.lowkey`
- copy `lk.py` into `~/.lowkey/lk.py`
- install the `lk` command into `~/.foundry/bin/lk`
- make the custom Foundry command available immediately

## Use it

```bash
lk --help
```

## Source layout

```text
foundry-lowkey/
├── bin/
│   └── lk
├── lowkey/
│   └── lk.py
├── install.sh
├── README.md
└── .gitignore
```

## Notes

This is meant to be portable across machines. The project files are stored in GitHub, and the installer patches your local Foundry installation without needing to copy the whole Solidity project.
