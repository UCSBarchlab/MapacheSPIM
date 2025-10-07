#!/usr/bin/env python3
"""
Test console disasm command
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mapachespim.console import MapacheSPIMConsole


def test_console_disasm():
    """Test the disasm console command"""
    print("Testing console disasm command...")

    console = MapacheSPIMConsole(verbose=False)
    console.stdout = sys.stdout

    # Load test program
    console.onecmd('load examples/test_simple/simple')
    print()

    # Test disasm command
    print("Test 1: Disassemble 5 instructions from entry point")
    console.onecmd('disasm 0x80000000 5')

    print("\nTest 2: Disassemble using alias")
    console.onecmd('d 0x80000000 3')

    print("\nTest 3: Disassemble default count (10)")
    console.onecmd('disasm 0x80000000')

    print("\n✓ Console disasm command test complete!")


if __name__ == '__main__':
    test_console_disasm()
