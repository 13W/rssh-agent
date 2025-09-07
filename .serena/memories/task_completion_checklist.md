# Task Completion Checklist

When completing any coding task in the rssh-agent project, ensure you:

## Before Starting
1. Understand the specification in `spec.md`
2. Check the implementation checklist in `checklist.md`
3. Review existing code for patterns and conventions

## During Development
1. Follow Rust 2024 edition patterns
2. Use existing error types from rssh-core
3. Implement proper error handling with Result types
4. Add appropriate logging with tracing
5. Ensure thread/async safety where needed
6. Apply security best practices (zeroize, permissions, validation)

## After Implementation
1. **Format code**: Run `cargo fmt` to ensure consistent formatting
2. **Lint check**: Run `cargo clippy -- -D warnings` and fix all warnings
3. **Run tests**: Execute `cargo test` to ensure nothing is broken
4. **Test specific changes**: Run focused tests for modified components
5. **Build check**: Run `cargo build` to ensure compilation succeeds
6. **Documentation**: Update or add doc comments for new/modified public APIs

## Before Committing (if asked)
1. Verify all tests pass
2. Ensure no clippy warnings
3. Check formatting is correct
4. Review changes with `git diff`
5. Write clear commit message following project conventions

## Security Checklist
- [ ] No secrets or sensitive data in code
- [ ] Proper input validation
- [ ] Correct file permissions (0600/0700)
- [ ] Memory zeroization for sensitive data
- [ ] No unsafe code without safety documentation

## Quality Gates
The following must pass before considering a task complete:
- `cargo fmt -- --check` (no formatting issues)
- `cargo clippy -- -D warnings` (no warnings)
- `cargo test` (all tests pass)
- `cargo build` (successful compilation)