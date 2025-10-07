Command Line Usage Guide
====================

This guide covers using MapacheSim as a SPIM-like assembly simulator from the command line.

Quick Start
----------

1. Install MapacheSim:

   .. code-block:: bash

      pip install mapachesim

2. Run the interactive console:

   .. code-block:: bash

      mapache

3. Or run an assembly file directly:

   .. code-block:: bash

      mapache path/to/program.asm

Interactive Console
----------------

The interactive console provides a SPIM-like environment for debugging and running assembly programs.

Basic Commands
~~~~~~~~~~~~

* ``load <file.asm>`` - Load an assembly file
* ``step`` - Execute one instruction
* ``run`` - Run until completion
* ``regs`` - Display registers
* ``mem text`` - Display text segment
* ``mem data`` - Display data segment
* ``help`` - Show all available commands

Example Session
~~~~~~~~~~~~~

Here's an example session running a factorial program:

.. code-block:: text

   $ mapache
   Loading "Mips" processor model.
   Welcome to MapacheSIM. Type help or ? to list commands.

   (mapache) load factorial.asm
   (mapache) step
   0000010000: addiu $2 $0 4
   (mapache) regs
   $0 = 0x00000000  $at= 0x00000000  $v0= 0x00000004  $v1= 0x00000000
   $a0= 0x00000000  $a1= 0x00000000  $a2= 0x00000000  $a3= 0x00000000
   ...

Memory Display
~~~~~~~~~~~~

Use ``mem text`` and ``mem data`` to examine memory contents:

.. code-block:: text

   (mapache) mem text
   0x00010000:  24 02 00 04  3c 04 00 04  34 84 00 00  00 00 00 0c
   0x00010010:  24 02 00 05  00 40 20 20  0c 00 40 11  00 40 28 20
   ...

   (mapache) mem data
   0x00040000:  0a 45 6e 74  65 72 20 61  20 6e 75 6d  62 65 72 3a
   0x00040010:  20 00 0a 46  61 63 74 6f  72 69 61 6c  20 69 73 3a
   ...

Running Programs
-------------

There are several ways to run programs:

1. Interactive stepping:

   .. code-block:: text

      (mapache) step
      0000010000: addiu $2 $0 4
      (mapache) step
      0000010004: lui $4 4

2. Run until completion:

   .. code-block:: text

      (mapache) run

3. Run directly from command line:

   .. code-block:: bash

      mapache factorial.asm

4. Run quietly (no output except program output):

   .. code-block:: bash

      mapache factorial.asm -q

Debugging Features
---------------

Breakpoints
~~~~~~~~~~

Set and manage breakpoints:

.. code-block:: text

   (mapache) break 0x10020    # Set breakpoint at address
   (mapache) break main       # Set breakpoint at label
   (mapache) info break       # List breakpoints
   (mapache) delete 1         # Delete breakpoint #1
   (mapache) clear           # Clear all breakpoints

Single Stepping
~~~~~~~~~~~~~

Step through code with different levels of detail:

.. code-block:: text

   (mapache) step            # Execute one instruction
   (mapache) pstep           # Step with register display
   (mapache) continue        # Run until next breakpoint

Error Handling
------------

MapacheSim provides helpful error messages for common issues:

1. Assembly errors:
   
   .. code-block:: text

      (mapache) load invalid.asm
      Assembly Error: Line 5: Invalid instruction format

2. Runtime errors:

   .. code-block:: text

      Runtime Machine Error: Invalid memory access at 0x10100

3. File errors:

   .. code-block:: text

      Error: Cannot find file "missing.asm" to load. 