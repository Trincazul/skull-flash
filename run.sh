#!/bin/bash

source venv/bin/activate

# Forward all arguments to the skull-flash CLI entry point.
# Examples:
#   ./run.sh --help
#   ./run.sh scan --target 192.168.1.1 --ports 1-1000
#   ./run.sh osint --target example.com --subdomains
#   ./run.sh interactive        # v1 menu (backward compat)
skull-flash "$@"