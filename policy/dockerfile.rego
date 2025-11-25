package main

# Dockerfile Security Policy
# Open Policy Agent (OPA) / Conftest policy for Dockerfile validation

# Deny using 'latest' tag for base images
deny[msg] {
  input[i].Cmd == "from"
  val := split(input[i].Value[0], ":")
  contains(val[1], "latest")
  msg = sprintf("Line %d: Avoid using 'latest' tag for base images - use specific versions for reproducibility", [i])
}

# Deny running as root (no USER directive)
deny[msg] {
  not has_user_directive
  msg = "No USER directive found - container will run as root (security risk)"
}

# Warn if no HEALTHCHECK is defined
warn[msg] {
  not has_healthcheck_directive
  msg = "No HEALTHCHECK directive found - consider adding health checks for better container orchestration"
}

# Warn if using ADD instead of COPY
warn[msg] {
  input[i].Cmd == "add"
  msg = sprintf("Line %d: Consider using COPY instead of ADD unless you need tar extraction or URL fetching", [i])
}

# Deny if exposing privileged ports (< 1024)
deny[msg] {
  input[i].Cmd == "expose"
  port := to_number(input[i].Value[0])
  port < 1024
  msg = sprintf("Line %d: Avoid exposing privileged port %d (ports < 1024 require root)", [i, port])
}

# Warn if no maintainer/label metadata
warn[msg] {
  not has_label_directive
  not has_maintainer_directive
  msg = "No LABEL or MAINTAINER directive found - consider adding metadata for documentation"
}

# Helper functions
has_user_directive {
  input[_].Cmd == "user"
}

has_healthcheck_directive {
  input[_].Cmd == "healthcheck"
}

has_label_directive {
  input[_].Cmd == "label"
}

has_maintainer_directive {
  input[_].Cmd == "maintainer"
}
