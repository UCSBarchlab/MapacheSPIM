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
.isa mips32


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
    la      $a0, welcome
    li      $v0, 4
    syscall

    la      $a0, title
    li      $v0, 4
    syscall

    la      $a0, welcome
    li      $v0, 4
    syscall

    la      $a0, rules
    li      $v0, 4
    syscall

    # Load the secret number into $s0 (saved register)
    la      $t0, secret
    lw      $s0, 0($t0)         # $s0 = secret number

    # Initialize guess counter
    li      $s1, 0              # $s1 = 0 (number of guesses)

# ============================================================================
# game_loop: Main game loop
# ============================================================================
game_loop:
    # Print prompt
    la      $a0, prompt
    li      $v0, 4
    syscall

    # Read user's guess
    li      $v0, 5              # Syscall 5 = read_int
    syscall                     # Result is in $v0
    move    $t1, $v0            # $t1 = user's guess

    # Increment guess counter
    addi    $s1, $s1, 1

    # Compare guess with secret
    beq     $t1, $s0, win       # if guess == secret, we win!
    blt     $t1, $s0, guess_low # if guess < secret, too low

    # If we get here, guess > secret (too high)
    la      $a0, too_high
    li      $v0, 4
    syscall
    j       game_loop           # Try again

guess_low:
    la      $a0, too_low
    li      $v0, 4
    syscall
    j       game_loop           # Try again

# ============================================================================
# win: Player guessed correctly!
# ============================================================================
win:
    # Print victory message
    la      $a0, correct1
    li      $v0, 4
    syscall

    la      $a0, correct2
    li      $v0, 4
    syscall

    # Print number of guesses
    move    $a0, $s1
    li      $v0, 1
    syscall

    # Print "try!" or "tries!" depending on count
    li      $t0, 1
    beq     $s1, $t0, one_guess # if count == 1, use singular

    la      $a0, correct3       # "tries!"
    li      $v0, 4
    syscall
    j       end_game

one_guess:
    la      $a0, one_try        # "try!"
    li      $v0, 4
    syscall

end_game:
    # Print thank you message
    la      $a0, thanks
    li      $v0, 4
    syscall

    # Exit program
    li      $v0, 10
    syscall

# ============================================================================
# SYSCALL REFERENCE
# ============================================================================
#
#   Syscall #1  (print_int):    Print integer in $a0
#   Syscall #4  (print_string): Print string at address in $a0
#   Syscall #5  (read_int):     Read integer, result in $v0
#   Syscall #10 (exit):         Exit program
#
# ============================================================================
# HOW THE GAME WORKS
# ============================================================================
#
# 1. The secret number (42 by default) is loaded into register $s0
# 2. A counter ($s1) tracks how many guesses the player makes
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
# MIPS vs RISC-V DIFFERENCES
# ============================================================================
#
#   RISC-V              MIPS
#   ------              ----
#   beq  t1, s0, win    beq $t1, $s0, win   (same syntax)
#   blt  t1, s0, low    blt $t1, $s0, low   (pseudo-instruction)
#   j    game_loop      j   game_loop       (unconditional jump)
#   lw   s0, 0(t0)      lw  $s0, 0($t0)     (load word)
#   mv   t1, v0         move $t1, $v0       (move register)
#   addi s1, s1, 1      addi $s1, $s1, 1    (add immediate)
#   s0-s7 (saved)       $s0-$s7 (saved)
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
