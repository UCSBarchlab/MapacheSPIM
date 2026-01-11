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
# ============================================================================
.isa arm64


    .data

# The secret number - change this to play with different values!
secret:     .word   42

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
    adr     x0, welcome
    mov     x8, #4
    svc     #0

    adr     x0, title
    mov     x8, #4
    svc     #0

    adr     x0, welcome
    mov     x8, #4
    svc     #0

    adr     x0, rules
    mov     x8, #4
    svc     #0

    # Load the secret number into x19 (callee-saved register)
    adr     x9, secret
    ldr     w19, [x9]       # x19 = secret number (use w19 for 32-bit load)

    # Initialize guess counter
    mov     x20, #0         # x20 = number of guesses

# ============================================================================
# game_loop: Main game loop
# ============================================================================
game_loop:
    # Print prompt
    adr     x0, prompt
    mov     x8, #4
    svc     #0

    # Read user's guess
    mov     x8, #5          # Syscall 5 = read_int
    svc     #0              # Result is in x0

    # Increment guess counter
    add     x20, x20, #1

    # Store guess in x9 for comparisons
    mov     x9, x0          # x9 = user's guess

    # Compare guess with secret
    cmp     x9, x19         # Compare guess with secret
    b.eq    win             # if guess == secret, we win!
    b.lt    guess_low       # if guess < secret, too low

    # If we get here, guess > secret (too high)
    adr     x0, too_high
    mov     x8, #4
    svc     #0
    b       game_loop       # Try again

guess_low:
    adr     x0, too_low
    mov     x8, #4
    svc     #0
    b       game_loop       # Try again

# ============================================================================
# win: Player guessed correctly!
# ============================================================================
win:
    # Print victory message
    adr     x0, correct1
    mov     x8, #4
    svc     #0

    adr     x0, correct2
    mov     x8, #4
    svc     #0

    # Print number of guesses
    mov     x0, x20
    mov     x8, #1
    svc     #0

    # Print "try!" or "tries!" depending on count
    cmp     x20, #1
    b.eq    one_guess       # if count == 1, use singular

    adr     x0, correct3    # "tries!"
    mov     x8, #4
    svc     #0
    b       end_game

one_guess:
    adr     x0, one_try     # "try!"
    mov     x8, #4
    svc     #0

end_game:
    # Print thank you message
    adr     x0, thanks
    mov     x8, #4
    svc     #0

    # Exit program
    mov     x8, #10
    svc     #0

# ============================================================================
# SYSCALL REFERENCE
# ============================================================================
#
#   Syscall #1  (print_int):    Print integer in x0
#   Syscall #4  (print_string): Print string at address in x0
#   Syscall #5  (read_int):     Read integer, result in x0
#   Syscall #10 (exit):         Exit program
#
# ============================================================================
# HOW THE GAME WORKS
# ============================================================================
#
# 1. The secret number (42 by default) is loaded into register x19
# 2. A counter (x20) tracks how many guesses the player makes
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
# ARM64 vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              ARM64
#   ------              -----
#   beq t1, s0, win     cmp x9, x19 + b.eq win   (compare + branch)
#   blt t1, s0, low     cmp x9, x19 + b.lt low   (compare + branch)
#   j   game_loop       b   game_loop            (unconditional branch)
#   lw  s0, 0(t0)       ldr w19, [x9]            (load word)
#   mv  t1, a0          mov x9, x0               (move register)
#   addi s1, s1, 1      add x20, x20, #1         (add immediate)
#   s0-s11 (saved)      x19-x28 (callee-saved)
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
