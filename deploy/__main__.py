"""`python -m deploy` -- entry point, per design doc §8.2."""
import sys

from deploy.cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
