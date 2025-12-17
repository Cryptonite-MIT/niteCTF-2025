# Stronk Rabin Solution

1. Query `DEC` to gather all possible sum combinations of plaintexts
2. the largest and the smallest sum would be of the form `x`, `-x (mod n)` use this to recover `n`
3. the crt sum would yield a combination that pairs to `2 mod n` thus, in possible plaintexts there exists `2 * m (mod n)`
4. so just multiply 2 inverse mod n to all retrieved sum combinations, look for flag format, get flag

[Solve script](solve.py)
