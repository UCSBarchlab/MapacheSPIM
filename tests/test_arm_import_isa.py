#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

print("1. Importing with ISA")
from mapachespim import create_simulator, ISA
print("2. Import successful")

print("3. Creating simulator")
sim = create_simulator("examples/arm/test_simple/simple")
print("4. Success!")
