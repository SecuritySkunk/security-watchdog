#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# lm-generate.sh - LM Studio Code Generation Helper for Thermidor
# ═══════════════════════════════════════════════════════════════════════════
#
# Usage:
#   ./lm-generate.sh <system-prompt-file> <user-prompt-file> [output-file]
#
# Example:
#   ./lm-generate.sh prompts/system.txt prompts/task.txt output/chunk1.ts
#
# Environment Variables:
#   LM_STUDIO_URL     - LM Studio server URL (default: http://10.0.0.229:1234)
#   LM_MODEL          - Model to use (default: qwen2.5-coder-32b-instruct)
#   LM_TEMPERATURE    - Generation temperature (default: 0.2)
#   LM_MAX_TOKENS     - Max output tokens (default: 8192)

set -e

# ─── Configuration ───────────────────────────────────────────────────────────
LM_STUDIO_URL="${LM_STUDIO_URL:-http://10.0.0.229:1234}"
LM_MODEL="${LM_MODEL:-qwen2.5-coder-32b-instruct}"
LM_TEMPERATURE="${LM_TEMPERATURE:-0.2}"
LM_MAX_TOKENS="${LM_MAX_TOKENS:-8192}"

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ─── Functions ───────────────────────────────────────────────────────────────
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

check_server() {
    log_info "Checking LM Studio server at ${LM_STUDIO_URL}..."
    if ! curl -s --connect-timeout 5 "${LM_STUDIO_URL}/v1/models" > /dev/null 2>&1; then
        log_error "Cannot connect to LM Studio at ${LM_STUDIO_URL}"
        log_error "Ensure LM Studio is running and the server is started."
        exit 1
    fi
    log_success "LM Studio server is reachable"
}

escape_json() {
    # Escape special characters for JSON
    python3 -c "import json, sys; print(json.dumps(sys.stdin.read()))"
}

# ─── Main ────────────────────────────────────────────────────────────────────
if [ $# -lt 2 ]; then
    echo "Usage: $0 <system-prompt-file> <user-prompt-file> [output-file]"
    echo ""
    echo "Options (via environment variables):"
    echo "  LM_STUDIO_URL   - Server URL (default: http://10.0.0.229:1234)"
    echo "  LM_MODEL        - Model name (default: qwen2.5-coder-32b-instruct)"
    echo "  LM_TEMPERATURE  - Temperature (default: 0.2)"
    echo "  LM_MAX_TOKENS   - Max tokens (default: 8192)"
    exit 1
fi

SYSTEM_FILE="$1"
USER_FILE="$2"
OUTPUT_FILE="${3:-/dev/stdout}"

# Validate input files
if [ ! -f "$SYSTEM_FILE" ]; then
    log_error "System prompt file not found: $SYSTEM_FILE"
    exit 1
fi

if [ ! -f "$USER_FILE" ]; then
    log_error "User prompt file not found: $USER_FILE"
    exit 1
fi

# Check server connectivity
check_server

# Read and escape prompts
log_info "Reading prompts..."
SYSTEM_PROMPT=$(cat "$SYSTEM_FILE" | escape_json)
USER_PROMPT=$(cat "$USER_FILE" | escape_json)

# Build request JSON
REQUEST_JSON=$(cat <<EOF
{
    "model": "${LM_MODEL}",
    "messages": [
        {"role": "system", "content": ${SYSTEM_PROMPT}},
        {"role": "user", "content": ${USER_PROMPT}}
    ],
    "temperature": ${LM_TEMPERATURE},
    "max_tokens": ${LM_MAX_TOKENS},
    "stream": false
}
EOF
)

# Make API call
log_info "Calling ${LM_MODEL} (temp=${LM_TEMPERATURE}, max_tokens=${LM_MAX_TOKENS})..."
START_TIME=$(date +%s)

RESPONSE=$(curl -s -X POST "${LM_STUDIO_URL}/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_JSON")

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Check for errors
if echo "$RESPONSE" | jq -e '.error' > /dev/null 2>&1; then
    ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // .error')
    log_error "API Error: $ERROR_MSG"
    exit 1
fi

# Extract content
CONTENT=$(echo "$RESPONSE" | jq -r '.choices[0].message.content // empty')

if [ -z "$CONTENT" ]; then
    log_error "No content in response"
    echo "$RESPONSE" | jq . >&2
    exit 1
fi

# Write output
if [ "$OUTPUT_FILE" = "/dev/stdout" ]; then
    echo "$CONTENT"
else
    echo "$CONTENT" > "$OUTPUT_FILE"
    log_success "Output written to $OUTPUT_FILE (${DURATION}s)"
    
    # Show stats
    TOKENS_USED=$(echo "$RESPONSE" | jq -r '.usage.total_tokens // "unknown"')
    log_info "Tokens used: $TOKENS_USED"
fi
