# Changelog

## v1.0.0 (2024-03-14)

### Breaking

- Run scapy filter creation in the executor (#17) ([`e5965d3`](https://github.com/bdraco/aiodhcpwatcher/commit/e5965d335b8e02745ab727acef34bbb96f6a6076))

## v0.8.2 (2024-03-14)

### Fix

- Ensure all scapy modules are loaded in the executor (#16) ([`694c831`](https://github.com/bdraco/aiodhcpwatcher/commit/694c83121995ee756a50ef158be71bf50a600f65))

## v0.8.1 (2024-03-11)

### Fix

- Add a guard for when the options tuple is only one item (#15) ([`37a7371`](https://github.com/bdraco/aiodhcpwatcher/commit/37a7371693f693871947638bf85c69d7a1636bc1))

## v0.8.0 (2024-02-09)

### Feature

- Add support for setting nonblock with pcap (#14) ([`3287b50`](https://github.com/bdraco/aiodhcpwatcher/commit/3287b500ab4dc546257cdcb144746f7d8fa1d37c))

## v0.7.0 (2024-02-09)

### Feature

- Add helper to load scapy in the executor since it can block the loop (#13) ([`0ec1983`](https://github.com/bdraco/aiodhcpwatcher/commit/0ec19835ccd52e5c71c5d15c5e48c0382b4aea4f))

## v0.6.0 (2024-02-08)

### Feature

- Add test coverage for broken filtering (#12) ([`c23d934`](https://github.com/bdraco/aiodhcpwatcher/commit/c23d934e6f86c031bb25a309edaff607b255596d))

## v0.5.0 (2024-02-08)

### Feature

- Decode hostnames using idna encoding (#10) ([`111cdfe`](https://github.com/bdraco/aiodhcpwatcher/commit/111cdfefcfc621c7ef3d001d8b9f8e2b85460ef2))

## v0.4.0 (2024-02-08)

### Feature

- Increase coverage (#9) ([`6280898`](https://github.com/bdraco/aiodhcpwatcher/commit/6280898a4a55cc3e0feed3e6b78c453038419c5e))

## v0.3.3 (2024-02-08)

### Fix

- Add checks for perm error setting up reader (#8) ([`58b4025`](https://github.com/bdraco/aiodhcpwatcher/commit/58b40253abcefb71deb17c7d87c706a3f47f15fe))

## v0.3.2 (2024-02-08)

### Fix

- Ensure filter can be created on macos (#7) ([`8c00359`](https://github.com/bdraco/aiodhcpwatcher/commit/8c0035964b249eeedc684f19794a99d93a3317a0))

## v0.3.1 (2024-02-08)

### Fix

- Import order (#6) ([`3acbb20`](https://github.com/bdraco/aiodhcpwatcher/commit/3acbb202a4cbfee1fa41595ac5b746c485c1c04e))

## v0.3.0 (2024-02-08)

### Feature

- Refactor to make more testable (#4) ([`ddd6d84`](https://github.com/bdraco/aiodhcpwatcher/commit/ddd6d84c8246b05384b92fa7edf45fca5bed6a92))

## v0.2.0 (2024-02-08)

### Feature

- Cleanups (#2) ([`fdfd1b6`](https://github.com/bdraco/aiodhcpwatcher/commit/fdfd1b66fc11a20930c8a869bcb8766c0156cb8c))

## v0.1.0 (2024-02-08)

### Feature

- Init (#1) ([`188b4b3`](https://github.com/bdraco/aiodhcpwatcher/commit/188b4b315ce3303cdeab9eeb8fa8f8eed2e185ec))

## v0.0.0 (2024-02-08)
