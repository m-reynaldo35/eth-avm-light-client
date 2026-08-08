"""`python -m relayer` -- entry point. Mirrors deploy/__main__.py."""
import sys

from relayer.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
