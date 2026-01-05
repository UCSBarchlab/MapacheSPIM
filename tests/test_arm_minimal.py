#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

print("1. About to import")
from mapachespim import create_simulator
print("2. Import successful")

print("3. About to create simulator")
sim = create_simulator("examples/arm/test_simple/simple")
print("4. Simulator created")

print("5. About to step")
result = sim.step()
print(f"6. Step result: {result.name}")
