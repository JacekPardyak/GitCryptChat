# python -m pip install PyNaCl
from pathlib import Path
from nacl.public import PrivateKey, PublicKey, Box
import nacl.utils


# ---------- Katalogi ----------

PRIVATE_KEYS = Path("private/keys")
PUBLIC_KEYS = Path("public/keys")
MESSAGES = Path("public/messages")

for directory in (PRIVATE_KEYS, PUBLIC_KEYS, MESSAGES):
    directory.mkdir(parents=True, exist_ok=True)


# ---------- Generowanie kluczy ----------

user_id = "jac"

user_key = PrivateKey.generate()
user_pubkey = user_key.public_key

# Klucz prywatny
(PRIVATE_KEYS / f"{user_id}_key.bin").write_bytes(
    bytes(user_key)
)

# Klucz publiczny
(PUBLIC_KEYS / f"{user_id}_pubkey.bin").write_bytes(
    bytes(user_pubkey)
)


# ---------- Szyfrowanie wiadomości ----------

sender_id = "vito"
recipient_id = "jac"
message = "желтый гусли само"
message_id = "msg_001"

sender_key_path = PRIVATE_KEYS / f"{sender_id}_key.bin"
recipient_pubkey_path = PUBLIC_KEYS / f"{recipient_id}_pubkey.bin"

# Odczyt kluczy
sender_key = PrivateKey(sender_key_path.read_bytes())
recipient_pubkey = PublicKey(recipient_pubkey_path.read_bytes())

# Kodowanie UTF-8
msg = message.encode("utf-8")

# Box: klucz prywatny nadawcy + publiczny odbiorcy
box = Box(sender_key, recipient_pubkey)

# Jawnie generujemy nonce, aby zapisać go osobno jak w R
nonce = nacl.utils.random(Box.NONCE_SIZE)

encrypted = box.encrypt(msg, nonce)

# Zapis szyfrogramu bez nonce
message_path = MESSAGES / f"{message_id}.bin"
message_path.write_bytes(encrypted.ciphertext)

# Zapis nonce
nonce_path = MESSAGES / f"{message_id}_nonce.bin"
nonce_path.write_bytes(encrypted.nonce)


# ---------- Deszyfrowanie wiadomości ----------

sender_id = "vito"
recipient_id = "jac"
message_id = "msg_001"

sender_pubkey_path = PUBLIC_KEYS / f"{sender_id}_pubkey.bin"
recipient_key_path = PRIVATE_KEYS / f"{recipient_id}_key.bin"
message_path = MESSAGES / f"{message_id}.bin"
nonce_path = MESSAGES / f"{message_id}_nonce.bin"

recipient_key = PrivateKey(recipient_key_path.read_bytes())
sender_pubkey = PublicKey(sender_pubkey_path.read_bytes())
ciphertext = message_path.read_bytes()
nonce = nonce_path.read_bytes()

# Klucz prywatny odbiorcy + publiczny nadawcy
box = Box(recipient_key, sender_pubkey)

decrypted = box.decrypt(ciphertext, nonce)

# Odczyt tekstu UTF-8
print(decrypted.decode("utf-8"))
