
# Szyfrowanie symetryczne

library(sodium)

# Generowanie tajnego klucza
key <- keygen()

# Wiadomość do zaszyfrowania
message <- charToRaw("Tajna wiadomość")
rawToChar(message)

# Szyfrowanie
ciphertext <- data_encrypt(message, key)

# Odszyfrowanie
decrypted <- data_decrypt(ciphertext, key)

# Konwersja z powrotem na tekst
rawToChar(decrypted)

# Szyfrowanie asymetryczne

# Bob generuje parę kluczy
bob_key <- keygen()
bob_pubkey <- pubkey(bob_key)

# Alice przygotowuje wiadomość
msg <- charToRaw("Cześć Bob!")

# Alice szyfruje wiadomość kluczem publicznym Boba
ciphertext <- simple_encrypt(msg, bob_pubkey)

# Bob odszyfrowuje wiadomość swoim kluczem prywatnym
decrypted <- simple_decrypt(ciphertext, bob_key)

rawToChar(decrypted)

# Szyfrowanie i uwierzytelnianie nadawcy

# Alice generuje klucze
alice_key <- keygen()
alice_pubkey <- pubkey(alice_key)

# Bob generuje klucze
bob_key <- keygen()
bob_pubkey <- pubkey(bob_key)

# Alice szyfruje wiadomość dla Boba
msg <- charToRaw("Poufna wiadomość od Alice")

ciphertext <- auth_encrypt(
  msg,
  alice_key,
  bob_pubkey
)

# Bob odszyfrowuje i sprawdza nadawcę
decrypted <- auth_decrypt(
  ciphertext,
  bob_key,
  alice_pubkey
)

rawToChar(decrypted)
