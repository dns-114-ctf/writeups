import hashlib

username = b"BENNETT"
digest = hashlib.sha256(username).hexdigest()

positions = [4, 5, 3, 6, 2, 7, 1, 8]
dynamic_part = "".join(digest[i] for i in positions)

print("SHA-256 :", digest)
print("Cle :", f"picoCTF{{1n_7h3_kk3y_of_{dynamic_part}}}")
