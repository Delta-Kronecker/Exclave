#!/bin/bash

source "bin/lib/ipbf/init.sh"

export CC_aarch64_linux_android=$ANDROID_ARM64_CC
export AR_aarch64_linux_android=$ANDROID_AR
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$ANDROID_ARM64_CC

rustup target add aarch64-linux-android 2>/dev/null || true

cd "$IPBF_PATH" || exit 1
cargo build --release --target aarch64-linux-android --lib --no-default-features || exit 1

JNILIBS="$PROJECT/app/src/main/jniLibs"
mkdir -p "$JNILIBS/arm64-v8a"
cp -f target/aarch64-linux-android/release/lib$LIB_NAME.so "$JNILIBS/arm64-v8a/"