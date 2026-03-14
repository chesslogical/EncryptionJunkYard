#!/bin/bash
# all.sh - Concatenate Cargo.toml and all src/*.rs files into all.txt
# Usage: run from the same directory as Cargo.toml

OUTPUT_FILE="all.txt"

# Empty / create the output file
> "$OUTPUT_FILE"

# Function to append a file with a header
append_file() {
    local file="$1"
    echo "==================== FILE: $file ====================" >> "$OUTPUT_FILE"
    cat "$file" >> "$OUTPUT_FILE"
    echo -e "\n\n" >> "$OUTPUT_FILE"
}

# Add Cargo.toml first
if [ -f "Cargo.toml" ]; then
    append_file "Cargo.toml"
else
    echo "Cargo.toml not found!"
    exit 1
fi

# Add all Rust source files in src/
if [ -d "src" ]; then
    for src_file in src/*.rs; do
        [ -f "$src_file" ] && append_file "$src_file"
    done
else
    echo "src directory not found!"
    exit 1
fi

echo "All files have been concatenated into $OUTPUT_FILE"
