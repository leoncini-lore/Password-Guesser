# Password Guesser
Password Guesser is a C project that performs a brute-force attack on hashed passwords stored in a Unix-like shadow file using dictionary words and multithreading to maximize performance. It includes two programs: parallel_number.c, which splits password variations among threads for each user, and parallel_user.c, which divides users among threads. Each dictionary word is transformed into several forms (including substitutions and capitalization) and combined with numerical suffixes to extend the search space. The dictionary is fully loaded into memory to optimize execution speed. This project is for educational purposes only.

Author: Lorenzo Leoncini
