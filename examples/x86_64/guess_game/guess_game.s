# ============================================================================
# guess_game.s - Number Guessing Game
# ============================================================================
#
# An interactive game that demonstrates:
#   1. Reading user input (read_int syscall)
#   2. Game loop with win condition
#   3. Conditional logic (too high, too low, correct)
#   4. Counting iterations
#
# Try to guess the secret number! The program will tell you if your
# guess is too high or too low.
#
# Note: This uses AT&T syntax (GNU assembler style)
# ============================================================================
.isa x86_64


    .data

# The secret number - change this to play with different values!
secret:     .long   42

# Game messages
welcome:    .asciz  "================================\n"
title:      .asciz  "   NUMBER GUESSING GAME\n"
rules:      .asciz  "Guess a number between 1 and 100\n"
prompt:     .asciz  "\nEnter your guess: "
too_low:    .asciz  "Too low! Try a higher number.\n"
too_high:   .asciz  "Too high! Try a lower number.\n"
correct1:   .asciz  "\n*** CORRECT! ***\n"
correct2:   .asciz  "You guessed it in "
correct3:   .asciz  " tries!\n"
one_try:    .asciz  " try!\n"
thanks:     .asciz  "\nThanks for playing!\n"

    .text
    .globl _start

# ============================================================================
# _start: Program Entry Point
# ============================================================================
_start:
    # Print welcome banner
    leaq    welcome(%rip), %rdi
    movq    $4, %rax
    syscall

    leaq    title(%rip), %rdi
    movq    $4, %rax
    syscall

    leaq    welcome(%rip), %rdi
    movq    $4, %rax
    syscall

    leaq    rules(%rip), %rdi
    movq    $4, %rax
    syscall

    # Load the secret number into r12 (callee-saved register)
    leaq    secret(%rip), %rax
    movl    (%rax), %r12d           # r12 = secret number

    # Initialize guess counter
    xorq    %r13, %r13              # r13 = 0 (number of guesses)

# ============================================================================
# game_loop: Main game loop
# ============================================================================
game_loop:
    # Print prompt
    leaq    prompt(%rip), %rdi
    movq    $4, %rax
    syscall

    # Read user's guess
    movq    $5, %rax                # Syscall 5 = read_int
    syscall                         # Result is in rax

    # Increment guess counter
    incq    %r13

    # Store guess in r14 for comparisons
    movq    %rax, %r14              # r14 = user's guess

    # Compare guess with secret
    cmpq    %r12, %r14              # Compare guess with secret
    je      win                     # if guess == secret, we win!
    jl      guess_low               # if guess < secret, too low

    # If we get here, guess > secret (too high)
    leaq    too_high(%rip), %rdi
    movq    $4, %rax
    syscall
    jmp     game_loop               # Try again

guess_low:
    leaq    too_low(%rip), %rdi
    movq    $4, %rax
    syscall
    jmp     game_loop               # Try again

# ============================================================================
# win: Player guessed correctly!
# ============================================================================
win:
    # Print victory message
    leaq    correct1(%rip), %rdi
    movq    $4, %rax
    syscall

    leaq    correct2(%rip), %rdi
    movq    $4, %rax
    syscall

    # Print number of guesses
    movq    %r13, %rdi
    movq    $1, %rax
    syscall

    # Print "try!" or "tries!" depending on count
    cmpq    $1, %r13
    je      one_guess               # if count == 1, use singular

    leaq    correct3(%rip), %rdi    # "tries!"
    movq    $4, %rax
    syscall
    jmp     end_game

one_guess:
    leaq    one_try(%rip), %rdi     # "try!"
    movq    $4, %rax
    syscall

end_game:
    # Print thank you message
    leaq    thanks(%rip), %rdi
    movq    $4, %rax
    syscall

    # Exit program
    movq    $10, %rax
    syscall

# ============================================================================
# SYSCALL REFERENCE
# ============================================================================
#
#   Syscall #1  (print_int):    Print integer in rdi
#   Syscall #4  (print_string): Print string at address in rdi
#   Syscall #5  (read_int):     Read integer, result in rax
#   Syscall #10 (exit):         Exit program
#
# ============================================================================
# HOW THE GAME WORKS
# ============================================================================
#
# 1. The secret number (42 by default) is loaded into register r12
# 2. A counter (r13) tracks how many guesses the player makes
# 3. Each iteration:
#    - Prompt the user for input
#    - Read their guess using syscall #5
#    - Compare guess to secret:
#      - Equal? Jump to win condition
#      - Less? Print "too low" and loop
#      - Greater? Print "too high" and loop
# 4. When correct, print the number of attempts and exit
#
# ============================================================================
# x86-64 vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              x86-64 (AT&T syntax)
#   ------              --------------------
#   beq t1, s0, win     cmpq %r12, %r14 + je win  (compare + jump)
#   blt t1, s0, low     cmpq %r12, %r14 + jl low  (compare + jump)
#   j   game_loop       jmp  game_loop            (unconditional jump)
#   lw  s0, 0(t0)       movl (%rax), %r12d        (load word)
#   mv  t1, a0          movq %rax, %r14           (move register)
#   addi s1, s1, 1      incq %r13                 (increment)
#   s0-s11 (saved)      r12-r15, rbx, rbp (callee-saved)
#
# ============================================================================
# EXERCISES FOR STUDENTS
# ============================================================================
#
# 1. Change the secret number and play the game
# 2. Add a maximum number of guesses (e.g., 7 tries)
# 3. Add input validation (check if guess is between 1 and 100)
# 4. Add a "play again?" feature after winning
# 5. Keep track of best score across multiple games
#
# ============================================================================
