
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
      textInput(
        "user_id",
        "User ID",
        value = "alice"
      ),
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
        "sender_id",
        "Sender ID",
        value = "bob"
      ),
      
      textInput(
        "recipient_id",
        "Recipient ID",
        value = "alice"
      ),
      
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
        "sender_id_dec",
        "Sender ID",
        value = "bob"
      ),
      
      textInput(
        "recipient_id_dec",
        "Recipient ID",
        value = "alice"
      ),
      
      textInput(
        "message_id_dec", 
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
      
      # An user
      user_key <- sodium::keygen()
      user_pubkey <- sodium::pubkey(user_key)
      
      # Private key
      saveRDS(
        user_key,
        glue::glue("private/keys/{input$user_id}_key.rds")
      )

      # Public key
      saveRDS(
        user_pubkey,
        glue::glue("public/keys/{input$user_id}_pubkey.rds")
      )
      

      key_status(
        paste(
          "Keys generated successfully.",
          glue::glue("{input$user_id}'s private key: private/keys/{input$user_id}_key.rds"),
          glue::glue("{input$user_id}'s public key: public/keys/{input$user_id}_pubkey.rds"),
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
      
      sender_path <- glue::glue("private/keys/{input$sender_id}_key.rds")
      recipient_pub_path <- glue::glue("public/keys/{input$recipient_id}_pubkey.rds")
      
      if (!file.exists(sender_path) ||
          !file.exists(recipient_pub_path)) {
        stop("Najpierw wygeneruj klucze w zakładce Key generation.")
      }
      
      # Wczytanie kluczy
      sender_key <- readRDS(sender_path)
      recipient_pubkey <- readRDS(recipient_pub_path)
      
      # Tekst -> surowe bajty
      msg <- charToRaw(enc2utf8(input$message))
      
      # Szyfrowanie i uwierzytelnianie
      ciphertext <- sodium::auth_encrypt(
        msg,
        sender_key,
        recipient_pubkey
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
      
      if (!valid_id(input$message_id_dec)) {
        stop("Message ID może zawierać tylko litery, cyfry, _ i -.")
      }
      
      # Klucz prywatny odbiorcy
      recipient_key_path <- glue::glue(
        "private/keys/{input$recipient_id_dec}_key.rds"
      )
      
      # Klucz publiczny nadawcy
      sender_pubkey_path <- glue::glue(
        "public/keys/{input$sender_id_dec}_pubkey.rds"
      )
      
      message_path <- file.path(
        "public/messages",
        paste0(input$message_id_dec, ".rds")
      )
      
      if (!file.exists(recipient_key_path)) {
        stop("Nie znaleziono klucza prywatnego odbiorcy.")
      }
      
      if (!file.exists(sender_pubkey_path)) {
        stop("Nie znaleziono klucza publicznego nadawcy.")
      }
      
      if (!file.exists(message_path)) {
        stop("Nie znaleziono wskazanej wiadomości.")
      }
      
      # Wczytanie kluczy i szyfrogramu
      recipient_key <- readRDS(recipient_key_path)
      sender_pubkey <- readRDS(sender_pubkey_path)
      ciphertext <- readRDS(message_path)
      
      # Odszyfrowanie i weryfikacja nadawcy
      decrypted <- sodium::auth_decrypt(
        ciphertext,
        recipient_key,
        sender_pubkey
      )
      
      decrypted_message(rawToChar(decrypted))

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
