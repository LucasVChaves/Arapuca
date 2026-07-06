#!/usr/bin/env bash
# populate_docs.sh - fills a target dir with a variety of low-entropy "normal" files
# Usage: ./populate_docs.sh /path/to/watch_dir 3000   (3000 = target MB)

set -euo pipefail
TARGET_DIR="${1:?usage: $0 <dir> <target_MB>}"
TARGET_MB="${2:-3000}"
mkdir -p "$TARGET_DIR"

extensions=(txt csv log md json xml docx pdf)
subdirs=(Documents Reports Invoices Projects Misc Photos_meta Contracts)

for s in "${subdirs[@]}"; do
    mkdir -p "$TARGET_DIR/$s"
done

written_mb=0
i=0
while (( written_mb < TARGET_MB )); do
    i=$((i+1))
    sub="${subdirs[$((RANDOM % ${#subdirs[@]}))]}"
    ext="${extensions[$((RANDOM % ${#extensions[@]}))]}"
    size_kb=$(( (RANDOM % 500) + 10 ))   # 10KB - 510KB per file
    fname="$TARGET_DIR/$sub/doc_$(printf '%05d' $i).$ext"

    # Low-entropy text
    yes "Line $i - Lorem ipsum dolor sit amet, consectetur adipiscing elit. Report data value $((RANDOM))." \
        | head -c "${size_kb}K" > "$fname"

    written_mb=$(( written_mb + size_kb / 1024 + 1 ))
    if (( i % 100 == 0 )); then
        echo "Written $i files, ~${written_mb}MB so far..."
    fi
done

echo "Done: $i files, ~${written_mb}MB in $TARGET_DIR"
