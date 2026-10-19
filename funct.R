library(sodium)

## Tab 1 - Key generation
user_id <- "vito"
user_key <- sodium::keygen()
user_pubkey <- sodium::pubkey(user_key)

writeBin(user_key, glue::glue("private/keys/{user_id}_key.bin"))
writeBin(user_pubkey, glue::glue("public/keys/{user_id}_pubkey.bin"))

## Tab 2 - Message encryption
sender_id <- "vito"
recipient_id <- "jac"
message <- "Ala ma kota \n zażółć gęślą jaźń"
message_id <- "msg_001"
sender_key_path <- glue::glue("private/keys/{sender_id}_key.bin")
recipient_pubkey_path <- glue::glue("public/keys/{recipient_id}_pubkey.bin")
sender_key <- readBin(sender_key_path, what = "raw", n = file.info(sender_key_path)$size)
recipient_pubkey <- readBin(recipient_pubkey_path, what = "raw", n = file.info(recipient_pubkey_path)$size)

msg <- charToRaw(enc2utf8(message))
ciphertext <- sodium::auth_encrypt(
  msg,
  sender_key,
  recipient_pubkey
)

message_path <- glue::glue("public/messages/{message_id}.bin")
writeBin(as.raw(ciphertext), message_path)

nonce <- attr(ciphertext, "nonce")
nonce_path <- glue::glue("public/messages/{message_id}_nonce.bin")
writeBin(as.raw(nonce), nonce_path)

## Tab 3 - Message decryption
sender_id <- "vito"
recipient_id <- "jac"
message_id <- "msg_001"

sender_pubkey_path <- glue::glue("public/keys/{sender_id}_pubkey.bin")
recipient_key_path <- glue::glue("private/keys/{recipient_id}_key.bin")
message_path <- glue::glue("public/messages/{message_id}.bin")
nonce_path <- glue::glue("public/messages/{message_id}_nonce.bin")

recipient_key <- readBin(recipient_key_path, what = "raw", n = file.info(recipient_key_path)$size)
sender_pubkey <- readBin(sender_pubkey_path, what = "raw", n = file.info(sender_pubkey_path)$size)
ciphertext <- readBin(message_path, what = "raw", n = file.info(message_path)$size)
nonce <- readBin(nonce_path, what = "raw", n = file.info(nonce_path)$size)

decrypted <- sodium::auth_decrypt(
  ciphertext,
  recipient_key,
  sender_pubkey,
  nonce
)
rawToChar(decrypted)


# Tab 4 - File encryption

sender_id <- "vito"
recipient_id <- "jac"

# Ścieżka do dowolnego pliku, który chcesz zaszyfrować
input_file_path <- "private/messages/Untitled.pdf"

# Identyfikator zaszyfrowanego pliku
file_id <- "file_001"

# Ścieżki do kluczy
sender_key_path <- glue::glue("private/keys/{sender_id}_key.bin")
recipient_pubkey_path <- glue::glue("public/keys/{recipient_id}_pubkey.bin")

sender_key <- readBin(
  sender_key_path,
  what = "raw",
  n = file.info(sender_key_path)$size
)

recipient_pubkey <- readBin(
  recipient_pubkey_path,
  what = "raw",
  n = file.info(recipient_pubkey_path)$size
)

# Odczyt pliku jako danych binarnych
file_data <- readBin(
  input_file_path,
  what = "raw",
  n = file.info(input_file_path)$size
)

# Szyfrowanie pliku
ciphertext <- sodium::auth_encrypt(
  file_data,
  sender_key,
  recipient_pubkey
)

# Zapis zaszyfrowanego pliku
encrypted_file_path <- glue::glue(
  "public/messages/{file_id}.bin"
)

writeBin(
  as.raw(ciphertext),
  encrypted_file_path
)

# Zapis nonce
nonce <- attr(ciphertext, "nonce")

nonce_path <- glue::glue(
  "public/messages/{file_id}_nonce.bin"
)

writeBin(
  as.raw(nonce),
  nonce_path
)


# Tab 5 - File decryption

sender_id <- "vito"
recipient_id <- "jac"

# Identyfikator zaszyfrowanego pliku
file_id <- "file_001"

# Ścieżka, pod którą zostanie odtworzony oryginalny plik
output_file_path <- "private/messages/dokument.pdf"

# Ścieżki do kluczy
sender_pubkey_path <- glue::glue(
  "public/keys/{sender_id}_pubkey.bin"
)

recipient_key_path <- glue::glue(
  "private/keys/{recipient_id}_key.bin"
)

encrypted_file_path <- glue::glue(
  "public/messages/{file_id}.bin"
)

nonce_path <- glue::glue(
  "public/messages/{file_id}_nonce.bin"
)

# Odczyt kluczy
recipient_key <- readBin(
  recipient_key_path,
  what = "raw",
  n = file.info(recipient_key_path)$size
)

sender_pubkey <- readBin(
  sender_pubkey_path,
  what = "raw",
  n = file.info(sender_pubkey_path)$size
)

# Odczyt zaszyfrowanego pliku i nonce
ciphertext <- readBin(
  encrypted_file_path,
  what = "raw",
  n = file.info(encrypted_file_path)$size
)

nonce <- readBin(
  nonce_path,
  what = "raw",
  n = file.info(nonce_path)$size
)

# Deszyfrowanie pliku
decrypted <- sodium::auth_decrypt(
  ciphertext,
  recipient_key,
  sender_pubkey,
  nonce
)

# Zapis odszyfrowanych danych do pliku
writeBin(
  decrypted,
  output_file_path
)


## Tab 6 - Github synchronization
user.name <- "John Doe"
user.email <- "john.doe@mail.com"
  
system("git remote -v")
system(glue::glue('git config --global user.name "{user.name}"'))
system(glue::glue('git config --global user.email "{user.email}"'))
system("git pull")
system("git add .")
system('git commit -m "Aktualizacja aplikacji"')
system("git push")
