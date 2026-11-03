import sys

from .doctor import main

if len(sys.argv) > 1 and sys.argv[1] == "doctor":
    sys.exit(main(sys.argv[2:]))
sys.exit(main(sys.argv[1:]))
