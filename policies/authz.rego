package authz

# Default deny
default allow = false

# Single rule with all conditions
allow = true if {
    # Check if user role exists
    input.user_role != ""

    # Allow if either condition is met:
    # 1. It's public data
    # 2. User is admin
    any([
        input.path == "public-data",
        input.user_role == "admin"
    ])

    # Extra check: deny sensitive data for non-admins
    not (input.path == "sensitive-data" and input.user_role != "admin")
} 