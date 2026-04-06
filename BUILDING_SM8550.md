# OnePlus 11 (SM8550) Local Build Quickstart

If your build fails with `.config not found`, run the helper script below.

## Prerequisites

Install host tools similar to the CI workflow:

```bash
sudo apt-get update
sudo apt-get install -y bc bison build-essential cpio flex git kmod \
  libelf-dev libssl-dev lz4 python3 rsync unzip xz-utils zstd \
  device-tree-compiler clang lld llvm
```

On Arch/CachyOS use:

```bash
sudo pacman -Syu --needed base-devel flex bison clang lld llvm aarch64-linux-gnu-binutils
```

## Configure + build

```bash
./scripts/build-sm8550.sh
```

The script performs:
1. `defconfig`
2. fragment merge (`sm8550.config`, `op11.config`, `hardening.config`)
3. `olddefconfig`
4. build `Image`, `Image.gz`, `dtbs`, and `modules`

Build logs are saved at `out/build-sm8550.log` (or `<out-dir>/build-sm8550.log`
if you override `--out-dir`).

## Troubleshooting

- `Error 2` during `defconfig` with `flex: not found` or similar means host
  tools are missing. Re-run the prerequisite install command above.
- `The source tree is not clean, please run 'make ARCH=arm64 mrproper'` means
  previous in-tree artifacts exist (for example a top-level `.config`). Run:
  ```bash
  make ARCH=arm64 mrproper
  ```
  then start the helper script again.

## Useful options

- Configure only:
  ```bash
  ./scripts/build-sm8550.sh --configure-only
  ```
- Custom output directory:
  ```bash
  ./scripts/build-sm8550.sh --out-dir out-sm8550
  ```
- Limit parallel jobs:
  ```bash
  ./scripts/build-sm8550.sh --jobs 8
  ```
