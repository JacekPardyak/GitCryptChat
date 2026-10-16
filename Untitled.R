library(sodium)

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
rawToChar(out)

# interesting property
tmp <- auth_decrypt(ciphertext, bob_key, alice_pubkey)
stopifnot(identical(out, tmp))
          