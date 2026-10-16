
library(shiny)
library(sodium)

# Katalogi aplikacji
dir.create("private/keys", recursive = TRUE, showWarnings = FALSE)
dir.create("public/keys", recursive = TRUE, showWarnings = FALSE)
dir.create("public/messages", recursive = TRUE, showWarnings = FALSE)

ui <- fluidPage(
  titlePanel("Sodium Messenger"),
  
  tabsetPanel(
    id = "tabs",
    
    # TAB 1: GENEROWANIE KLUCZY
    tabPanel(
      "Key generation",
      br(),
      h4("Generate cryptographic keys"),
      p("Generuje pary kluczy dla Alice i Boba."),
      
      actionButton(
        "generate_keys",
        "Generate keys",
        class = "btn-primary"
      ),
      
      br(), br(),
      verbatimTextOutput("key_status")
    ),
    
    # TAB 2: SZYFROWANIE
    tabPanel(
      "Message encryption",
      br(),
      h4("Encrypt a message"),
      
      textInput(
        "message_id",
        "Message ID",
        value = "msg_001"
      ),
      
      textAreaInput(
        "message",
        "Message",
        value = "Tajna wiadomość dla Boba od Alice",
        rows = 5
      ),
      
      actionButton(
        "encrypt",
        "Encrypt message",
        class = "btn-primary"
      ),
      
      br(), br(),
      verbatimTextOutput("encrypt_status")
    ),
    
    # TAB 3: ODSZYFROWYWANIE
    tabPanel(
      "Message decryption",
      br(),
      h4("Decrypt a message"),
      
      textInput(
        "decrypt_id",
        "Message ID",
        value = "msg_001"
      ),
      
      actionButton(
        "decrypt",
        "Decrypt message",
        class = "btn-primary"
      ),
      
      br(), br(),
      h4("Decrypted message"),
      verbatimTextOutput("decrypted_message"),
      
      h4("Status"),
      verbatimTextOutput("decrypt_status")
    )
  )
)

server <- function(input, output, session) {
  
  key_status <- reactiveVal("No keys generated.")
  encrypt_status <- reactiveVal("")
  decrypted_message <- reactiveVal("")
  decrypt_status <- reactiveVal("")
  
  # Ograniczenie nazw plików, aby uniknąć ścieżek
  valid_id <- function(x) {
    is.character(x) &&
      length(x) == 1 &&
      grepl("^[A-Za-z0-9_-]+$", x)
  }
  
  output$key_status <- renderText(key_status())
  output$encrypt_status <- renderText(encrypt_status())
  output$decrypted_message <- renderText(decrypted_message())
  output$decrypt_status <- renderText(decrypt_status())
  
  # --------------------------------
  # TAB 1: GENEROWANIE KLUCZY
  # --------------------------------
  
  observeEvent(input$generate_keys, {
    
    tryCatch({
      
      # Alice
      alice_key <- sodium::keygen()
      alice_pubkey <- sodium::pubkey(alice_key)
      
      # Bob
      bob_key <- sodium::keygen()
      bob_pubkey <- sodium::pubkey(bob_key)
      
      # Klucze prywatne
      saveRDS(
        alice_key,
        "private/keys/alice_key.rds"
      )
      
      saveRDS(
        bob_key,
        "private/keys/bob_key.rds"
      )
      
      # Klucze publiczne
      saveRDS(
        alice_pubkey,
        "public/keys/alice_pubkey.rds"
      )
      
      saveRDS(
        bob_pubkey,
        "public/keys/bob_pubkey.rds"
      )
      
      key_status(
        paste(
          "Keys generated successfully.",
          "Alice private key: private/keys/alice_key.rds",
          "Bob private key: private/keys/bob_key.rds",
          "Alice public key: public/keys/alice_pubkey.rds",
          "Bob public key: public/keys/bob_pubkey.rds",
          sep = "\n"
        )
      )
      
      showNotification(
        "Key pairs generated successfully.",
        type = "message"
      )
      
    }, error = function(e) {
      
      key_status(
        paste("Key generation failed:", conditionMessage(e))
      )
      
      showNotification(
        "Key generation failed.",
        type = "error"
      )
    })
  })
  
  # --------------------------------
  # TAB 2: SZYFROWANIE WIADOMOŚCI
  # --------------------------------
  
  observeEvent(input$encrypt, {
    
    tryCatch({
      
      req(input$message)
      
      if (!valid_id(input$message_id)) {
        stop("Message ID może zawierać tylko litery, cyfry, _ i -.")
      }
      
      alice_path <- "private/keys/alice_key.rds"
      bob_pub_path <- "public/keys/bob_pubkey.rds"
      
      if (!file.exists(alice_path) ||
          !file.exists(bob_pub_path)) {
        stop("Najpierw wygeneruj klucze w zakładce Key generation.")
      }
      
      # Wczytanie kluczy
      alice_key <- readRDS(alice_path)
      bob_pubkey <- readRDS(bob_pub_path)
      
      # Tekst -> surowe bajty
      msg <- charToRaw(enc2utf8(input$message))
      
      # Szyfrowanie i uwierzytelnianie
      ciphertext <- sodium::auth_encrypt(
        msg,
        alice_key,
        bob_pubkey
      )
      
      # Zapis szyfrogramu
      out_path <- file.path(
        "public/messages",
        paste0(input$message_id, ".rds")
      )
      
      saveRDS(ciphertext, out_path)
      
      encrypt_status(
        paste(
          "Encryption successful.",
          paste("Saved to:", out_path),
          sep = "\n"
        )
      )
      
      showNotification(
        "Message encrypted and saved.",
        type = "message"
      )
      
    }, error = function(e) {
      
      encrypt_status(
        paste("Encryption failed:", conditionMessage(e))
      )
      
      showNotification(
        "Encryption failed.",
        type = "error"
      )
    })
  })
  
  # --------------------------------
  # TAB 3: ODSZYFROWYWANIE WIADOMOŚCI
  # --------------------------------
  
  observeEvent(input$decrypt, {
    
    tryCatch({
      
      if (!valid_id(input$decrypt_id)) {
        stop("Message ID może zawierać tylko litery, cyfry, _ i -.")
      }
      
      bob_path <- "private/keys/bob_key.rds"
      alice_pub_path <- "public/keys/alice_pubkey.rds"
      
      message_path <- file.path(
        "public/messages",
        paste0(input$decrypt_id, ".rds")
      )
      
      if (!file.exists(bob_path)) {
        stop("Nie znaleziono klucza prywatnego Boba.")
      }
      
      if (!file.exists(alice_pub_path)) {
        stop("Nie znaleziono klucza publicznego Alice.")
      }
      
      if (!file.exists(message_path)) {
        stop("Nie znaleziono wskazanej wiadomości.")
      }
      
      # Wczytanie kluczy i szyfrogramu
      bob_key <- readRDS(bob_path)
      alice_pubkey <- readRDS(alice_pub_path)
      ciphertext <- readRDS(message_path)
      
      # Odszyfrowanie i weryfikacja nadawcy
      decrypted <- sodium::auth_decrypt(
        ciphertext,
        bob_key,
        alice_pubkey
      )
      
      decrypted_message(
        rawToChar(decrypted)
      )
      
      decrypt_status(
        paste(
          "Decryption and authentication successful.",
          paste("File:", message_path),
          sep = "\n"
        )
      )
      
      showNotification(
        "Message decrypted and authenticated.",
        type = "message"
      )
      
    }, error = function(e) {
      
      decrypted_message("")
      
      decrypt_status(
        paste(
          "Decryption/authentication failed:",
          conditionMessage(e)
        )
      )
      
      showNotification(
        "Decryption failed. Check the keys and message.",
        type = "error"
      )
    })
  })
}

shinyApp(ui = ui, server = server)
