
# Szyfrowanie i uwierzytelnianie nadawcy

library(sodium)

# Alice generuje klucze
alice_key <- keygen()
alice_key |> saveRDS("./private/keys/alice_key.rds")
alice_pubkey <- "./private/keys/alice_key.rds" |> readRDS() |> pubkey()
alice_pubkey |> saveRDS("./public/keys/alice_pubkey.rds")

# Bob generuje klucze
bob_key <- keygen()
bob_key |> saveRDS("./private/keys/bob_key.rds")
bob_pubkey <- "./private/keys/bob_key.rds" |> readRDS() |> pubkey()
bob_pubkey |> saveRDS("./public/keys/bob_pubkey.rds")


# Alice szyfruje wiadomość dla Boba
#  readBin() gdy dane binarne
msg <- "./private/messages/msg_001.txt" |>
  readLines(encoding = "UTF-8") |>
  paste(collapse = "\n") |>
  charToRaw()

ciphertext <- auth_encrypt(
  msg,
  alice_key,
  bob_pubkey
)

ciphertext |> saveRDS("./public/messages/msg_001.rds")

# Bob odszyfrowuje i sprawdza nadawcę
ciphertext <- "./public/messages/msg_001.rds" |> readRDS()
  
decrypted <- auth_decrypt(
  ciphertext,
  bob_key,
  alice_pubkey
)

rawToChar(decrypted)

######
# Bob's keypair:
bob_key <- keygen()
bob_pubkey <- pubkey(bob_key)

# Alice's keypair:
alice_key <- keygen()
alice_pubkey <- pubkey(alice_key)

# Bob sends encrypted message for Alice:
msg <- charToRaw("TTIP is evil")
ciphertext <- auth_encrypt(msg, bob_key, alice_pubkey)

# Alice verifies and decrypts with her key
out <- auth_decrypt(ciphertext, alice_key, bob_pubkey)
stopifnot(identical(out, msg))

# Alice sends encrypted message for Bob
msg <- charToRaw("Let's protest")
ciphertext <- auth_encrypt(msg, alice_key, bob_pubkey)

# Bob verifies and decrypts with his key
out <- auth_decrypt(ciphertext, bob_key, alice_pubkey)
stopifnot(identical(out, msg))


