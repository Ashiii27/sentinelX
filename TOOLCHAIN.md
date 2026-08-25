# SentinelX Toolchain Specification

## Phase 0 — Supported Versions

This document specifies the minimum versions for building and running SentinelX v0.1.

### C++ Engine

- **CMake:** 3.16 or later
- **C++ Standard:** C++17 (C++20 features are not used)
- **Compiler:** GCC 9+ or Clang 10+ (Linux only for v0.1)
- **Linux Kernel:** Linux 4.15+ (for minimal BPF filter support)

#### Required Libraries (offline tests)
- **libpcap:** 1.10+ (optional; live capture disabled if unavailable)
  - On Ubuntu/Debian: `sudo apt-get install libpcap-dev`
  - On Alpine: `apk add libpcap-dev`

#### Optional Libraries
- **libcap:** 2.20+ (for dropping privileges after packet capture)
- **nlohmann/json:** 3.11+ (vendored or system; used for full alert JSON serialization)

### Node.js Backend

- **Node.js:** 18.x LTS or 20.x LTS
- **npm:** 9.x or later (included with Node.js)
- **MongoDB Driver:** mongoose ^8.0
- **Express:** ^4.18

#### Development Dependencies
- **TypeScript:** ^5.x (optional; backend is JavaScript for v0.1)
- **Mocha/Jest:** For unit tests (to be added in Phase 4)

### MongoDB

- **MongoDB:** 4.4+ (community or Atlas)
- **Connection:** MongoDB must be running on `mongodb://127.0.0.1:27017` by default
  - Configurable via `MONGODB_URL` environment variable

### Dashboard (Browser/Node.js Frontend)

- **Node.js:** Same as backend (18.x LTS or 20.x LTS)
- **React:** ^18.x
- **Vite:** ^4.x (build tool)

#### Target Browsers
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

### CI/CD

- **Linux CI Environment:** Ubuntu 22.04 LTS or later
- **Docker:** 20.10+ (for optional containerized build)

## Build Verification Checklist

A clean checkout on a supported Linux environment should:

1. Run `cmake -B build -DSENTINELX_BUILD_CAPTURE=OFF` without errors
2. Run `cmake --build build` and pass all C++ compilation
3. Run `ctest --output-on-failure` and pass all offline unit tests
4. Run `npm install` in `backend/` and `dashboard/` without errors
5. Start MongoDB locally and verify connection

## Platform-Specific Notes

### Linux (Primary)

- Most POSIX headers are available; tests do not require root privileges
- `malloc` and `new` must not throw; use `nothrow` or check return codes
- Avoid platform-specific syscalls; use POSIX equivalents

### macOS (Secondary - Not Tested in v0.1)

- libpcap is pre-installed; no additional dependencies needed
- Use `gmtime_s` or `thread_local` for thread-safe time functions
- May require `brew install libpcap-dev` for newer versions

### Windows (Not Supported for v0.1)

- Packet capture uses WinPcap/Npcap (not tested)
- live capture tests are opt-in and require Npcap
- Offline tests and backend remain compatible

## Version Lock and Updates

- **Engine C++ headers:** Versions are fixed in CMakeLists.txt
- **Backend npm:** Pinned in package.json and package-lock.json
- **Dashboard npm:** Pinned in package.json and package-lock.json
- **Updates:** Security patches are applied; major version upgrades are coordinated with a feature branch and Phase integration tests

## Testing Across Toolchain Versions

- **Unit Tests:** Run on every commit (CI)
- **Integration Tests:** Run after Phase 3 (Phase 6 checkout)
- **Deployment Tests:** Run after Phase 6; verify Docker images and systemd units on target OS

## Next Steps (Phase 1+)

- Phase 1: Add `.clang-tidy` and `.clang-format` for code quality
- Phase 4: Add ESLint + Prettier for backend/dashboard
- Phase 6: Add Docker Compose version pinning
- Phase 7: Consider C++20 features (modules, concepts) if needed
