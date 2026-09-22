# keygenme-py — Writeup

## Information
- Platform: CyLab Security Academy / picoCTF 2021
- Category: Reverse Engineering
- Difficulty: Medium
- Challenge author: syreal

## Challenge description
The challenge provides a Python script, `keygenme-trial.py`, simulating the trial version of a fictional piece of software ("Arcane Calculator"). The program asks for a license key to unlock the full version.

## Initial analysis
Reading the script reveals an `intro_trial()` function that displays a menu with 4 options, including `(c) Enter License Key`. The username hard-coded in the script is directly visible:

```python
username_trial = "BENNETT"
b_username_trial = b"BENNETT"
```

The expected key format is also present in plaintext:

```python
key_part_static1_trial = "picoCTF{1n_7h3_kk3y_of_"
key_part_dynamic1_trial = "xxxxxxxx"
key_part_static2_trial = "}"
key_full_template_trial = key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial
```

The final flag therefore has the form: `picoCTF{1n_7h3_kk3y_of_XXXXXXXX}`, where the 8 `X` characters remain to be determined.

## Identifying the vulnerability (keygen logic)
The `check_key(key, username_trial)` function validates the key character by character:

1. It first checks that the static part (`picoCTF{1n_7h3_kk3y_of_`) matches.
2. For each dynamic character, it compares a character of the provided key to a specific character of the SHA-256 hash of the username (`hashlib.sha256(username_trial).hexdigest()`), but **in a non-sequential order**.
3. Re-reading the source code, the index order used to pick from the hash is: `4, 5, 3, 6, 2, 7, 1, 8`.

This deliberate permutation of the indices is the program's only "protection": without reading the source code, it is impossible to guess the reconstruction order.

## Exploitation
A Python script exactly reproduces this logic to generate the valid key:

```python
import hashlib

username = b"BENNETT"
digest = hashlib.sha256(username).hexdigest()

positions = [4, 5, 3, 6, 2, 7, 1, 8]
dynamic_part = "".join(digest[i] for i in positions)

print("SHA-256:", digest)
print("Key:", f"picoCTF{{1n_7h3_kk3y_of_{dynamic_part}}}")
```

Execution:
```bash
python3 script.py
```

The generated key is then entered directly into the program's menu (option `c`), which validates the license and unlocks the full version (writing the `keygenme.py` file, not required to obtain the flag).

## Retrieving the flag
The generated license key directly corresponds to the flag expected by the platform:

```text
picoCTF{1n_7h3_kk3y_of_********}
```

## What this demonstrates
This challenge illustrates a classic reverse engineering technique: static reading of the source code (without execution or disassembly) is enough to extract the verification algorithm and reproduce it to forge a valid key (a "keygenning" technique).

## Fix
- Never hard-code the license generation/verification algorithm inside a distributable binary or script.
- Move license validation to the server side, with a secret never exposed client-side.
- Use an asymmetric cryptographic signature (e.g., RSA) rather than a simple hash derivable locally, to prevent any key reconstruction without the private secret.
