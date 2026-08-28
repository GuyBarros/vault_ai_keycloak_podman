package app.security

import rego.v1
import data.app.patterns

# Default to safe
default is_injection := false

# Logic 1: Handle Base64 encoded JSON structure
is_injection if {
    
    # Decode and verify it's JSON
    decoded := base64.decode(input)
    json.is_valid(decoded)
    
    # Unmarshal and search all strings within the JSON
    content := json.unmarshal(decoded)
    some _, value in walk(content)
    is_string(value)
    
    regex.match(patterns.prompt_injection_regex, value)
    
    print("Triggered: Injection detected in Base64-JSON. Match:", value)
}

# Logic 2: Handle Base64 encoded Raw String
is_injection if {
    
    # Decode and verify it's NOT JSON
    decoded := base64.decode(input)
    not json.is_valid(decoded)
    
    regex.match(patterns.prompt_injection_regex, decoded)
    
    print("Triggered: Injection detected in Base64-Raw String.")
}