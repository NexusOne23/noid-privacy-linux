# Contributing to Fortify

Thanks for your interest in Fortify! Here's how to contribute.

## Getting Started

1. Fork the repo
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/fortify.git`
3. Create a branch: `git checkout -b fix/your-change`
4. Make your changes
5. Test on at least one supported distro (Fedora, Ubuntu, Debian)
6. Submit a PR

## Code Style

- **Pure Bash.** No external dependencies (Python, Ruby, Node, etc.).
- Use the existing helper functions (`pass`, `fail`, `warn`, `info`, `header`).
- Follow the pattern of existing checks — one function per section.
- Quote all variables.
- Use `shellcheck` if available.

## Adding a New Check

1. Find the right section (or propose a new one).
2. Use `pass`/`fail`/`warn`/`info` for results.
3. Make sure it works on both Fedora/RHEL and Debian/Ubuntu.
4. Handle missing commands gracefully (`command -v` or `require_cmd`).
5. Add a `--skip` keyword if it's a new section.

## Good First Contributions

- Add telemetry detection for a new application
- Improve detection for your distro (Arch, openSUSE, etc.)
- Fix false positives you've encountered
- Improve documentation or examples
- Add translations

## Testing

```bash
# Syntax check
bash -n noid-privacy-linux.sh

# Run with verbose output
sudo bash noid-privacy-linux.sh

# Test specific sections
sudo bash noid-privacy-linux.sh --skip rootkit --skip containers
```

## Reporting Issues

- Include your distro and version
- Include the relevant Fortify output
- If it's a false positive, explain why

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0.

---

*Built by [Clawde](https://github.com/ClawdeRaccoon) 🦝*
