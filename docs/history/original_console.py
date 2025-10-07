'''The UCSB Mapache Interactive Architecture Simulator'''

# 1) catch error and exit on "step" (not just run)
# 2) convert step instruction decode use "fancy" register names
# 3) initialize the stack pointer correctly and reset the registers


import cmd
import signal
import math

from helpers import AssemblyError, ExecutionError, ExecutionComplete
from helpers import hexstr_to_int, decimalstr_to_int

import arch_mips
import arch_m248


def _chunk_list(lst, n):
    '''Chunk a list into a list of lists of length n.'''
    for i in range(0, len(lst), n):
        yield lst[i:i+n]


class MapacheConsole(cmd.Cmd):
    '''The Mapache Interactive Console. 

       The console handles all manner of error catching and presentation
       for the machine simulator and assembler in as an ISA independent
       manner as possible.'''

    intro = 'Welcome to MapacheSIM. Type help or ? to list commands.\n'
    prompt = '(mapache) '

    def __init__(self, verbose=True):
        super().__init__()
        self._verbose = verbose
        self.initialize()
        signal.signal(signal.SIGINT, handler=self.handler_sigint)
        self._interrupted = False # true when sigint has been caught
        self._running = False # true only during a "run"

    # --- Simualtion and Machine State --------------------------------------

    def initialize(self):
        #self.machine = m248.M248()
        self.machine = arch_mips.Mips()
        self.print_verbose(f'Loading "{type(self.machine).__name__}" processor model.')
        self.text_start_address = self.machine.text_start_address
        self.data_start_address = self.machine.data_start_address
        self.labels = {}
        self.breakpoints = {}
        # map 2MB chuncks of memory for emulation
        self.machine.mem_map(self.text_start_address, 2 * 1024 * 1024) # text and global
        self.machine.mem_map(0x7fe00000, 2 * 1024 * 1024) # stack

    def simulate(self, max_instructions=math.inf, print_each=False):
        '''Run the machine simulation forward until broken, used by "run", "continue", and "step".'''
        self._running = True
        stop_string = None
        instructions_executed = 0
        pc = None
        try:
            while instructions_executed < max_instructions:
                pc, ireturn = self.machine.step()
                instructions_executed += 1
                if self._interrupted:
                    self._interrupted = False
                    stop_string = 'interrupted'
                    break
                elif self.machine.PC in self.breakpoints:
                    stop_string = 'breakpoint'
                    break
                elif ireturn is ExecutionComplete:
                    stop_string = 'execution complete'
                    break
                elif print_each:
                    self.print_instruction(pc)
        except ExecutionError as e:
            pc = self.machine.PC
            stop_string = 'machine error'
            self.print_error(f'Runtime Machine Error: {e}')

        if stop_string:
            self.print_instruction(pc, stop_string)
        self._running = False
        return instructions_executed

    def load_text(self, code):
        '''Load a bytearray of code into instruction memory, and start up simulator.'''
        if code:
            self.machine.mem_write(self.text_start_address, code) # write code to emulated memory
            self.machine.PC = self.text_start_address # set pc using the setter

    def load_data(self, data):
        '''Load a bytearray in to the data segment and set up the rest of memory.'''
        if data:
            self.machine.mem_write(self.data_start_address, data) # write data segment to emulated memory 

    # --- Parsers and Printers --------------------------------------

    def parse_arg_as_address(self, arg):
        '''Take an argument and attempt convert it address (as a number or label).'''
        # TODO: add label conversion here
        addr = hexstr_to_int(arg)       
        if addr is None:
            addr = self.labels.get(arg, None)
        if addr is None:
            self.print_error(f'Error: Unable to parse hex address "{arg}"')
        return addr

    def parse_arg_as_integer(self, arg):
        '''Take an argument and attempt convert it to an integer (base 10).'''
        intval = decimalstr_to_int(arg)
        if intval is None:
            self.print_error(f'Error: Unable to parse as base 10 number "{arg}"')
        return intval

    def print_instruction(self, pc=None, note=None):
        '''Print the instruction at the provided address.
           If no "pc" is provided, the current pc is used.'''
        if not pc:  
            pc = self.machine.PC
        note_string = f'({note})' if note else ''
        raw_string = 'xx'*self.machine.isize
        dis_string = '<unknown>'
        try:
            current_instruction = self.machine.mem_read_instruction(pc)
            raw_string = f'{current_instruction:#010x}'
            dis_string = self.machine.disassemble(current_instruction, self.labels)
        except ExecutionError:
            pass
        print(f'[{pc:#010x}] {raw_string}   {dis_string} {note_string}')

    def print_registers(self):
        '''Helper function for printing register state.'''

        def rformat(rval):
            return f'{rval:#010x}'
            #return '0' if rval==0 else f'{rval:#010x}'

        def pprint_regs(reg_values):
            # TODO: check bits is not 32 and handle that case as well
            reg_formatted = [f'{name:<3}= {rformat(rval):>10}' for name,bits,rval in reg_values]
            for reg_line in _chunk_list(reg_formatted, 4):
                print('  '.join(reg_line))

        pprint_regs(self.machine.registers())

    def print_memory(self, start_addr, size=256, width=16, sep='  '):
        '''Helper function for printing memory state.'''

        def mformat(rval):
            return f'{rval:02x}'

        try:
            memory = self.machine.mem_read(start_addr, size)
            mem_formated = [mformat(b) for b in memory]
            print()
            for offset in range(0, size, width):
                addr = start_addr + offset
                row = mem_formated[offset:offset+width]
                mem_words = [' '.join(chunk) for chunk in _chunk_list(row, 4)]
                mem_row = sep.join(mem_words)
                print(f'{addr:#010x}:{sep}{mem_row}')
            print()
        except ExecutionError as e:
            self.print_error(e)

    def print_error(self, msg):
        '''Print a non-fatal error message to the user.'''
        print(f'\n{msg}\n')

    def print_verbose(self, *args, **kwargs):
        '''Print only if console set to verbose mode.'''
        if self._verbose:
            print(*args, **kwargs)

    #--- Command Handlers ----------------------------------

    def handler_sigint(self, signal, frame):
        self._interrupted = True
        print()
        if not self._running:
            self.do_exit(None)

    #def onecmd(self, line):
    #    ''' Catch any uncaught exceptions here. '''
    #    try:
    #        return super().onecmd(line)
    #    except Exception as e:
    #        self.print_error(f'Error: Uncaught Exception "{e}"')
    #        return False  # continue in cmd loop

    def do_settext(self, arg):
        'Set the text segment start address: e.g. "settext 0x10000"'
        self.text_start_address = int(arg,16)

    def do_setdata(self, arg):
        'Set the data segment start address: e.g. "setdata 0x40000"'
        self.data_start_address = int(arg,16)

    def do_load(self, arg):
        'Load an assembly file into the simulator: e.g. "load filename.asm"'
        filename = arg
        try:
            tstart, dstart = self.text_start_address, self.data_start_address
            with open(filename,'r') as file:
                program = file.read()
            code, data, labels = self.machine.assembler.assemble(program, tstart, dstart)
            self.labels = labels
            self.machine.reset_registers()
            self.load_data(data)
            self.load_text(code) # this sets the PC
        except FileNotFoundError as e:
            self.print_error(f'Error: Cannot find file "{filename}" to load.')
        except IsADirectoryError as e:
            self.print_error(f'Error: Cannot load file "{filename}" because it is a directory.')
        except AssemblyError as e:
            self.print_error(f'Assembly Error: {e}')


    def do_step(self, arg):
        'Step the program execution forward N instructions: e.g. "step 3", "step"'
        if arg:
            n_steps = self.parse_arg_as_integer(arg)
        else:
            n_steps = 1
        if n_steps:
            self.simulate(n_steps, print_each=True)

    def do_pstep(self, arg):
        'Step the program execution forward and print other useful infomation: e.g. "pstep"'
        self.simulate(1, print_each=True)
        self.print_registers()
        print()

    def do_dis(self, arg):
        'Disassemble a hex sequence as an instruction: e.g. "decode 0x21290004", "decode 21 29 00 04"'
        hex_string = str.join('', arg.split())
        try:
            istring = self.machine.disassemble(hex_string, self.labels)
            print(f'{hex_string} -> {istring}')
        except:
            self.print_error(f'Error: Cannot diassasmble "{instr_string}".')

    def do_regs(self, arg):
        'Print the relavent registers of the processor: e.g. "regs"'
        print()
        self.print_registers()
        print()

    def do_mem(self, arg):
        'Print the specified regions of memory: e.g. "mem 0x40000", "mem text", "mem"'
        if arg == 'text':
            addr = self.text_start_address
        elif arg == 'data':
            addr = self.data_start_address
        elif arg == '':
            addr = self.data_start_address
        else:
            addr = self.parse_arg_as_address(arg)
        if addr is not None:
            self.print_memory(addr)

    def do_run(self, arg):
        'Run the loaded program. e.g. "run"'
        self.machine.reset_registers()
        self.machine.PC = self.text_start_address
        self.simulate()

    def do_continue(self, arg):
        'Continue running program after break. e.g. "continue"'
        self.simulate()

    def do_reinitialize(self, arg):
        'Clear the memory and registers and reload machine model. e.g. "reinitialize"'
        self.initialize()

    def do_breakpoint(self, arg):
        'Set a breakpoint at address or label. e.g. "breakpoint 0x1000C", "breakpoint foobar"'
        addr = self.parse_arg_as_address(arg)
        if addr is not None: 
            if addr % self.machine.isize != 0:
                self.print_error(f'Cannot add unaligned breakpoint to address "{addr}".')
            else:
                self.breakpoints[addr] = arg
                print(f'Added breakpoint at {addr:#010x} (named "{arg}").')

    def do_delete(self, arg):
        'Delete breakpoint at specificed address or label.'
        addr = self.parse_arg_as_address(arg)
        if addr is not None:
            if addr in self.breakpoints:
                del self.breakpoint[addr]
                print(f'Removed breakpoint from address "{addr:#010x}".')
            else:
                self.print_error(f'No breakpoint set at "{addr}".')

    def do_list(self, arg):
        'List all breakpoints. e.g. "list"'
        print()
        print(f'Currently tracking {len(self.breakpoints)} breakpoints.')
        for addr in self.breakpoints:
            print(f'  {addr:#010x}: {self.breakpoints[addr]}')
        print()

    def do_labels(self, arg):
        'List all labels. e.g. "labels"'
        print()
        print(f'Currently know of {len(self.labels)} labels.')
        for label in self.labels:
            print(f'  {self.labels[label]:#010x} <- {label}')
        print()

    def do_exit(self, arg):
        'Exit MapacheSIM: exit'
        print('\nThank you for using MapacheSIM :)\n') 
        exit()

    do_EOF = do_exit
    do_quit = do_exit

