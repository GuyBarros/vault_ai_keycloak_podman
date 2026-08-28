package app.masking

import rego.v1

# --- 1. Patterns & Templates (UI-Safe with Backticks and Asterisks) ---

# SSN: Masked digits in a code block
ssn_pattern      := `\d{3}-\d{2}-(\d{4})`
ssn_template     := "`***-**-$1`"

# Credit Card: Standardized * mask in a code block
cc_pattern       := `(?:\d[ -]*?){9,12}(\d{4})`
cc_template      := "`****-****-****-$1`"

# Email: Masks the username, keeps domain outside the block for readability
email_pattern    := `([a-zA-Z0-9._%+-])[a-zA-Z0-9._%+-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`
email_template   := "`$1***`@$2"

# IP Address: Octet masking in a code block
ip_pattern       := `(\d{1,3})\.\d{1,3}\.\d{1,3}\.(\d{1,3})`
ip_template      := "`$1.***.***.$2`"

# Phone: Masked exchange in a code block
phone_pattern    := `(?:\+?1[-. ]?)?\(?(\d{3})\)?[-. ]?(\d{3})[-. ]?(\d{4})`
phone_template   := "`($1) ***-$3`"

# AWS Key: Confirmed '*' works for OPA engine; backticks protect Streamlit UI
aws_key_pattern  := `(AKIA|ASIA)[0-9A-Z]{16}`
aws_key_template := "$1`****************`"

# Generic API Key: Explicit label in a code block
api_key_pattern  := `(?i)(api[\s\*_-]?key|secret|password|token)[\s\*:=]+([a-zA-Z0-9]{20,})`
api_key_template := "$1: `[REDACTED_SECRET]`"

# Log Patterns
log_pattern      := `(?i)\b(DEBUG|INFO|WARN|ERROR|FATAL)\b`
log_template     := "`[LOG_LEVEL:$1]`"

# --- 2. Decode the Input ---
decoded_input := base64.decode(input)

# --- 3. Main Logic: Check if JSON ---
masked_result := output if {
    json.is_valid(decoded_input)
    final_string := apply_all_masks(decoded_input)
    output := json.unmarshal(final_string)
}

# --- 4. Main Logic: Check if RAW STRING ---
masked_result := output if {
    not json.is_valid(decoded_input)
    output := apply_all_masks(decoded_input)
}

# --- Helper: Masking Chain ---
apply_all_masks(str) := result if {
    s1 := regex.replace(str, ssn_pattern, ssn_template)
    s2 := regex.replace(s1, cc_pattern, cc_template)
    s3 := regex.replace(s2, email_pattern, email_template)
    s4 := regex.replace(s3, ip_pattern, ip_template)
    s5 := regex.replace(s4, phone_pattern, phone_template)
    s6 := regex.replace(s5, aws_key_pattern, aws_key_template)
    s7 := regex.replace(s6, api_key_pattern, api_key_template)
    result := regex.replace(s7, log_pattern, log_template)
}