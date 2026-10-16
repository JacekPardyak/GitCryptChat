
# Szyfrowanie i uwierzytelnianie nadawcy

library(sodium)

# Alice generuje klucze
alice_key <- keygen()
saveRDS(alice_key, "../keys/alice_key.rds")
alice_pubkey <- "../keys/alice_key.rds" |> readRDS() |> pubkey()
saveRDS(alice_pubkey, "./keys/alice_pubkey.rds")

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
