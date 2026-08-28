package app.security

import rego.v1
import data.app.patterns

default is_unsafe := false

# --- Helper: Common Patterns ---
# We use a nested rule here. It won't show up in the output if you 
# query for 'is_unsafe' specifically, but to be safe, we call it inside.

# Logic 1: Treat decoded input as a JSON object and walk it
is_unsafe if {
    
    decoded := base64.decode(input)
    json.is_valid(decoded)
    
    content := json.unmarshal(decoded)
    some _, value in walk(content)
    is_string(value)
    
    print("Triggered: JSON block, match found in value:", value)
    
    # Using the imported pattern string
    regex.match(patterns.code_safety_regex, value)
}

# Logic 2: Treat decoded input as a raw string (if it's NOT JSON)
is_unsafe if {
    decoded := base64.decode(input)
    not json.is_valid(decoded)
    
    print("Triggered: RAW string block, match found in decoded input")
    
    # Using the imported pattern string
    regex.match(patterns.code_safety_regex, decoded)
}