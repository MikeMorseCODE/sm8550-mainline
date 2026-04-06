#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/build-sm8550.sh [--out-dir DIR] [--jobs N] [--configure-only]

Build helper for OnePlus 11 (SM8550) local builds.
- Generates .config from defconfig + fragments
- Runs olddefconfig
- Builds Image/Image.gz/dtbs/modules

Environment overrides:
  LLVM=1 LLVM_IAS=1
  CC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm
  OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip
USAGE
}

run_and_log() {
  local step="$1"
  shift

  echo "== ${step} =="
  if ! "$@" 2>&1 | tee -a "${LOG_FILE}"; then
    echo >&2
    echo "Step failed: ${step}" >&2
    echo "Last 120 lines from ${LOG_FILE}:" >&2
    tail -n 120 "${LOG_FILE}" >&2 || true
    exit 2
  fi
}

check_prereqs() {
  local -a required_tools=(
    make gcc flex bison
    clang ld.lld llvm-ar llvm-nm llvm-objcopy llvm-objdump llvm-strip
    aarch64-linux-gnu-ld
  )
  local missing=()
  local tool

  for tool in "${required_tools[@]}"; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
      missing+=("${tool}")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing required host tools: ${missing[*]}" >&2
    print_install_hint >&2
    exit 2
  fi
}

print_install_hint() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "Install with (Ubuntu/Debian):"
    echo "  sudo apt-get update && sudo apt-get install -y \\"
    echo "    build-essential flex bison clang lld llvm binutils-aarch64-linux-gnu"
  elif command -v pacman >/dev/null 2>&1; then
    echo "Install with (Arch/CachyOS):"
    echo "  sudo pacman -Syu --needed base-devel flex bison clang lld llvm aarch64-linux-gnu-binutils"
  elif command -v dnf >/dev/null 2>&1; then
    echo "Install with (Fedora):"
    echo "  sudo dnf install -y @development-tools flex bison clang lld llvm"
    echo "  # plus a package that provides aarch64-linux-gnu-ld for your Fedora release"
  elif command -v zypper >/dev/null 2>&1; then
    echo "Install with (openSUSE):"
    echo "  sudo zypper install -y -t pattern devel_C_C++ flex bison clang lld llvm"
    echo "  # plus a package that provides aarch64-linux-gnu-ld"
  else
    echo "Install your distro's build tools (flex, bison, clang/llvm/lld, and aarch64 cross-binutils)."
  fi
}

check_source_tree_clean() {
  if [[ -f ".config" || -d "include/config" || -d ".tmp_versions" ]]; then
    echo "Source tree appears dirty for O= builds." >&2
    echo "Run this once, then retry:" >&2
    echo "  make ARCH=arm64 mrproper" >&2
    exit 2
  fi
}

OUT_DIR="out"
JOBS="$(nproc --all)"
CONFIGURE_ONLY=0
LOG_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      OUT_DIR="$2"; shift 2 ;;
    --jobs|-j)
      JOBS="$2"; shift 2 ;;
    --configure-only)
      CONFIGURE_ONLY=1; shift ;;
    --help|-h)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2 ;;
  esac
done

check_prereqs
check_source_tree_clean

LOG_FILE="${OUT_DIR}/build-sm8550.log"

MAKE_FLAGS=(
  "ARCH=arm64"
  "SUBARCH=arm64"
  "LLVM=1"
  "LLVM_IAS=1"
  "CC=clang"
  "LD=ld.lld"
  "AR=llvm-ar"
  "NM=llvm-nm"
  "OBJCOPY=llvm-objcopy"
  "OBJDUMP=llvm-objdump"
  "STRIP=llvm-strip"
  "CROSS_COMPILE=aarch64-linux-gnu-"
  "O=${OUT_DIR}"
)

DEFCONFIG="defconfig"
CONFIG_FRAGMENTS=(
  "arch/arm64/configs/sm8550.config"
  "arch/arm64/configs/op11.config"
  "arch/arm64/configs/hardening.config"
)

mkdir -p "${OUT_DIR}"
: > "${LOG_FILE}"

echo "[1/3] Base config: ${DEFCONFIG}"
run_and_log "defconfig" make "${MAKE_FLAGS[@]}" "${DEFCONFIG}"

echo "[2/3] Merging fragments"
FRAGS=()
for frag in "${CONFIG_FRAGMENTS[@]}"; do
  if [[ -f "${frag}" ]]; then
    FRAGS+=("${frag}")
    echo "  + $(basename "${frag}")"
  else
    echo "  ! missing $(basename "${frag}") (skipping)"
  fi
done

if [[ ${#FRAGS[@]} -gt 0 ]]; then
  run_and_log "merge fragments" env KCONFIG_CONFIG="${OUT_DIR}/.config" \
    ./scripts/kconfig/merge_config.sh \
    -m -Q -O "${OUT_DIR}" "${OUT_DIR}/.config" "${FRAGS[@]}"
fi

run_and_log "olddefconfig" make "${MAKE_FLAGS[@]}" olddefconfig

echo "[3/3] Build"
if [[ "${CONFIGURE_ONLY}" -eq 1 ]]; then
  echo "Configuration completed at ${OUT_DIR}/.config"
  exit 0
fi

run_and_log "kernel build" make "${MAKE_FLAGS[@]}" -j"${JOBS}" Image Image.gz dtbs modules

echo
if [[ -f "${OUT_DIR}/arch/arm64/boot/Image" ]]; then
  echo "Build finished successfully: ${OUT_DIR}/arch/arm64/boot/Image"
  echo "Full log: ${LOG_FILE}"
else
  echo "Build did not produce Image; check output above." >&2
  exit 1
fi
