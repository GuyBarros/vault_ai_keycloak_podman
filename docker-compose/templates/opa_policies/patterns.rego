package app.patterns

import rego.v1

# We define the patterns as a set for easy reading
# then join them into a single regex string.
code_safety_regex := concat("|", [
    # --- 1. Language-Specific Code Execution ---
    `(?i)eval\s*\(`,
    `(?i)exec\s*\(`,
    `(?i)os\.system\s*\(`,
    `(?i)subprocess\.(Popen|call|run)\s*\(`,
    
    # --- 2. Destructive Shell Commands ---
    `(?i)rm\s+-rf`,
    `(?i)sudo\s+(rm|chmod|chown|dd|mkfs)`,
    `(?i)curl\s+.*\s*\|\s*(sudo\s+)?(bash|sh|zsh)`,
    
    # --- 3. Common Shell Utilities (New) ---
    # \b ensures we match 'ls' but not 'also'
    `(?i)\b(ls|cd|pwd|cat|mkdir|touch|whoami|id|uname|hostname|ps|top|kill|df|du)\s+`,
    `(?i)\b(python|python3|node|perl|php|ruby|gcc|g\+\+|make)\b`,

    # --- 4. Sensitive File Access & Traversal ---
    `(?i)/etc/passwd`,
    `(?i)/etc/shadow`,
    `(?i)\.env\b`,
    `(?i)\.\./\.\./` # Detects path traversal like ../../etc/passwd
])

prompt_injection_regex := concat("|", [
    # --- 1. Basic Overrides ---
    `(?i)(ignore|disregard|forget|skip|override)\s+(all|previous|system)?\s*(instructions|rules|directives)`,
    
    # --- 2. Roleplay & Persona Jailbreaks ---
    `(?i)(you are now|act as|persona:|take on the role of|hypothetically speaking)`,
    `(?i)(unfiltered|unrestricted|do anything now|DAN\s?mode)`,
    
    # --- 3. Prompt Leaking & Formatting Tricks ---
    `(?i)(print|show|output|reveal|repeat)\s+(the|your)?\s*(initial|system|hidden|original)?\s*(prompt|instructions|text)`,
    `(?i)(output|respond)\s+as\s+(code|json|markdown|base64|hex)`,
    
    # --- 4. Delimiter & Header Spoofing ---
    `(?i)(###\s*instruction|system:|user:|assistant:|admin:|<\|system\|>)`,
    
    # --- 5. Logic Hijacking ---
    `(?i)(the new rule is|from now on|end of previous conversation|start of new session)`,
    `(?i)(translate the following and then execute|summarize and then follow)`
])