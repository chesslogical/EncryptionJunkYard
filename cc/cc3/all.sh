#!/bin/bash
# all.sh - Dump Cargo.toml + src and tests into separate files
# Usage: run from the project root

ALL_FILE="all.txt"
TEST_FILE="test.txt"

# Empty / create output files
> "$ALL_FILE"
> "$TEST_FILE"

# Function to append a file with header
append_file() {
    local file="$1"
    local target="$2"
    echo "==================== FILE: $file ====================" >> "$target"
    cat "$file" >> "$target"
    echo -e "\n\n" >> "$target"
}

# Dump Cargo.toml + src/*.rs to all.txt
if [ -f "Cargo.toml" ]; then
    append_file "Cargo.toml" "$ALL_FILE"
else
    echo "Cargo.toml not found!"
    exit 1
fi

if [ -d "src" ]; then
    for src_file in src/*.rs; do
        [ -f "$src_file" ] && append_file "$src_file" "$ALL_FILE"
    done
else
    echo "src directory not found!"
    exit 1
fi

# Dump tests/*.rs to test.txt
if [ -d "tests" ]; then
    for test_file in tests/*.rs; do
        [ -f "$test_file" ] && append_file "$test_file" "$TEST_FILE"
    done
else
    echo "tests directory not found!"
    exit 1
fi

echo "All src and Cargo.toml files saved to $ALL_FILE"
echo "All test files saved to $TEST_FILE"
