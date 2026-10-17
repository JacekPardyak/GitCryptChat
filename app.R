
library(shiny)
library(sodium)
library(glue)

# ============================================================
# Konfiguracja i katalogi
# ============================================================

private_keys_dir <- "private/keys"
public_keys_dir  <- "public/keys"
messages_dir     <- "public/messages"

dir.create(private_keys_dir, recursive = TRUE, showWarnings = FALSE)
dir.create(public_keys_dir, recursive = TRUE, showWarnings = FALSE)
dir.create(messages_dir, recursive = TRUE, showWarnings = FALSE)

# Akceptujemy tylko bezpieczne identyfikatory plików.
valid_id <- function(x) {
  is.character(x) &&
    length(x) == 1L &&
    !is.na(x) &&
    grepl("^[A-Za-z0-9_-]{1,64}$", x)
}

read_raw_file <- function(path) {
  if (!file.exists(path)) {
    stop("Nie znaleziono pliku: ", path, call. = FALSE)
  }
  
  size <- file.info(path)$size
  
  if (is.na(size) || size <= 0) {
    stop("Plik jest pusty lub nie można go odczytać: ",
         path, call. = FALSE)
  }
  
  readBin(path, what = "raw", n = size)
}

list_users <- function(kind = c("public", "private")) {
  kind <- match.arg(kind)
  
  folder <- if (kind == "public") {
    public_keys_dir
  } else {
    private_keys_dir
  }
  
  suffix <- if (kind == "public") "_pubkey.bin$" else "_key.bin$"
  files <- list.files(folder, pattern = suffix, full.names = FALSE)
  
  sub(suffix, "", files)
}

list_messages <- function() {
  files <- list.files(
    messages_dir,
    pattern = "^[A-Za-z0-9_-]+\\.bin$",
    full.names = FALSE
  )
  
  sub("\\.bin$", "", files)
}

# ============================================================
# Interfejs użytkownika
# ============================================================

ui <- fluidPage(
  titlePanel("Secure Messenger — szyfrowanie wiadomości"),
  
  tags$head(
    tags$style(HTML("
      .section-panel {
        padding: 18px;
        margin-top: 15px;
        border: 1px solid #ddd;
        border-radius: 8px;
      }
      .hint {
        color: #666;
        margin-top: 8px;
      }
      textarea {
        font-family: monospace;
      }
    "))
  ),
  
  tabsetPanel(
    id = "main_tabs",
    
    # --------------------------------------------------------
    # TAB 1: Generowanie kluczy
    # --------------------------------------------------------
    tabPanel(
      title = "1. Generowanie kluczy",
      
      div(
        class = "section-panel",
        
        h3("Generowanie pary kluczy"),
        
        p(
          "Każdy użytkownik posiada klucz prywatny oraz odpowiadający ",
          "mu klucz publiczny."
        ),
        
        textInput(
          "key_user_id",
          "Identyfikator użytkownika",
          value = "jac",
          placeholder = "np. jac"
        ),
        
        actionButton(
          "generate_keys",
          "Wygeneruj klucze",
          class = "btn-primary"
        ),
        
        br(), br(),
        verbatimTextOutput("key_result"),
        
        hr(),
        h4("Zarejestrowani użytkownicy"),
        actionButton("refresh_users", "Odśwież listę"),
        tableOutput("users_table")
      )
    ),
    
    # --------------------------------------------------------
    # TAB 2: Szyfrowanie
    # --------------------------------------------------------
    tabPanel(
      title = "2. Szyfrowanie",
      
      div(
        class = "section-panel",
        
        h3("Szyfrowanie wiadomości"),
        
        selectizeInput(
          "enc_sender",
          "Nadawca — klucz prywatny",
          choices = list_users("private"),
          options = list(placeholder = "Wybierz nadawcę")
        ),
        
        selectizeInput(
          "enc_recipient",
          "Odbiorca — klucz publiczny",
          choices = list_users("public"),
          options = list(placeholder = "Wybierz odbiorcę")
        ),
        
        textInput(
          "enc_message_id",
          "Identyfikator wiadomości",
          value = "msg_001"
        ),
        
        textAreaInput(
          "enc_message",
          "Treść wiadomości",
          value = "Ala ma kota\nzażółć gęślą jaźń",
          rows = 6,
          width = "100%"
        ),
        
        actionButton(
          "encrypt_message",
          "Zaszyfruj wiadomość",
          class = "btn-primary"
        ),
        
        br(), br(),
        verbatimTextOutput("encrypt_result")
      )
    ),
    
    # --------------------------------------------------------
    # TAB 3: Odszyfrowywanie
    # --------------------------------------------------------
    tabPanel(
      title = "3. Odszyfrowywanie",
      
      div(
        class = "section-panel",
        
        h3("Odszyfrowanie wiadomości"),
        
        selectizeInput(
          "dec_sender",
          "Nadawca — klucz publiczny",
          choices = list_users("public"),
          options = list(placeholder = "Wybierz nadawcę")
        ),
        
        selectizeInput(
          "dec_recipient",
          "Odbiorca — klucz prywatny",
          choices = list_users("private"),
          options = list(placeholder = "Wybierz odbiorcę")
        ),
        
        selectizeInput(
          "dec_message_id",
          "Identyfikator wiadomości",
          choices = list_messages(),
          options = list(placeholder = "Wybierz wiadomość")
        ),
        
        actionButton(
          "refresh_messages",
          "Odśwież wiadomości"
        ),
        
        br(), br(),
        
        actionButton(
          "decrypt_message",
          "Odszyfruj wiadomość",
          class = "btn-primary"
        ),
        
        br(), br(),
        verbatimTextOutput("decrypt_result"),
        
        h4("Odszyfrowana treść"),
        textAreaInput(
          "decrypted_text",
          NULL,
          value = "",
          rows = 6,
          width = "100%",
          placeholder = "Tutaj pojawi się odszyfrowana wiadomość"
        )
      )
    ),
    
    # --------------------------------------------------------
    # TAB 4: GitHub
    # --------------------------------------------------------
    tabPanel(
      title = "4. Synchronizacja Git",
      
      div(
        class = "section-panel",
        
        h3("Synchronizacja repozytorium"),
        
        p(
          "Operacje są wykonywane w katalogu roboczym aplikacji. ",
          "Przed synchronizacją upewnij się, że repozytorium Git ",
          "jest skonfigurowane i uwierzytelnione."
        ),
        
        textInput(
          "git_user_name",
          "Nazwa użytkownika Git",
          value = "John Doe"
        ),
        
        textInput(
          "git_user_email",
          "Adres e-mail Git",
          value = "john.doe@mail.com"
        ),
        
        checkboxInput(
          "git_confirm",
          "Potwierdzam, że sprawdziłem pliki przeznaczone do publikacji",
          value = FALSE
        ),
        
        actionButton(
          "git_status",
          "Sprawdź status"
        ),
        
        actionButton(
          "git_sync",
          "Synchronizuj",
          class = "btn-primary"
        ),
        
        br(), br(),
        verbatimTextOutput("git_result"),
        
        p(
          class = "hint",
          "Synchronizacja obejmuje pliki aplikacji oraz katalog public/. ",
          "Katalog private/ jest pomijany."
        )
      )
    )
  )
)

# ============================================================
# Logika serwera
# ============================================================

server <- function(input, output, session) {
  
  key_status <- reactiveVal(
    "Gotowy do generowania kluczy."
  )
  
  enc_status <- reactiveVal(
    "Gotowy do szyfrowania."
  )
  
  dec_status <- reactiveVal(
    "Gotowy do odszyfrowywania."
  )
  
  git_status_text <- reactiveVal(
    "Gotowy do synchronizacji."
  )
  
  # ----------------------------------------------------------
  # Aktualizacja list wyboru
  # ----------------------------------------------------------
  
  refresh_user_choices <- function() {
    updateSelectizeInput(
      session, "enc_sender",
      choices = list_users("private"),
      server = TRUE
    )
    
    updateSelectizeInput(
      session, "enc_recipient",
      choices = list_users("public"),
      server = TRUE
    )
    
    updateSelectizeInput(
      session, "dec_sender",
      choices = list_users("public"),
      server = TRUE
    )
    
    updateSelectizeInput(
      session, "dec_recipient",
      choices = list_users("private"),
      server = TRUE
    )
  }
  
  refresh_message_choices <- function() {
    updateSelectizeInput(
      session,
      "dec_message_id",
      choices = list_messages(),
      server = TRUE
    )
  }
  
  observeEvent(input$refresh_users, {
    refresh_user_choices()
  })
  
  observeEvent(input$refresh_messages, {
    refresh_message_choices()
  })
  
  output$users_table <- renderTable({
    private_users <- list_users("private")
    public_users <- list_users("public")
    users <- sort(unique(c(private_users, public_users)))
    
    if (length(users) == 0) {
      return(data.frame(
        Informacja = "Brak wygenerowanych kluczy."
      ))
    }
    
    data.frame(
      Użytkownik = users,
      `Klucz prywatny` = ifelse(
        users %in% private_users, "Dostępny lokalnie", "Brak"
      ),
      `Klucz publiczny` = ifelse(
        users %in% public_users, "Dostępny", "Brak"
      ),
      check.names = FALSE
    )
  }, striped = TRUE, bordered = TRUE, spacing = "s")
  
  # ----------------------------------------------------------
  # TAB 1: Generowanie kluczy
  # ----------------------------------------------------------
  
  observeEvent(input$generate_keys, {
    tryCatch({
      user_id <- input$key_user_id
      
      if (!valid_id(user_id)) {
        stop(
          "Identyfikator może zawierać tylko litery ASCII, ",
          "cyfry, podkreślenia i myślniki (maks. 64 znaki)."
        )
      }
      
      private_path <- file.path(
        private_keys_dir,
        paste0(user_id, "_key.bin")
      )
      
      public_path <- file.path(
        public_keys_dir,
        paste0(user_id, "_pubkey.bin")
      )
      
      if (file.exists(private_path) || file.exists(public_path)) {
        stop(
          "Klucze dla tego użytkownika już istnieją. ",
          "Nie nadpisuję istniejących kluczy."
        )
      }
      
      user_key <- sodium::keygen()
      user_pubkey <- sodium::pubkey(user_key)
      
      # Plik tymczasowy pozwala ograniczyć ryzyko pozostawienia
      # niekompletnego zestawu kluczy.
      temp_private <- tempfile(tmpdir = private_keys_dir)
      temp_public <- tempfile(tmpdir = public_keys_dir)
      
      on.exit({
        unlink(c(temp_private, temp_public))
      }, add = TRUE)
      
      writeBin(user_key, temp_private)
      writeBin(user_pubkey, temp_public)
      
      if (!file.rename(temp_private, private_path)) {
        stop("Nie udało się zapisać klucza prywatnego.")
      }
      
      if (!file.rename(temp_public, public_path)) {
        unlink(private_path)
        stop("Nie udało się zapisać klucza publicznego.")
      }
      
      Sys.chmod(private_path, mode = "0600")
      
      key_status(paste0(
        "Sukces!\n",
        "Użytkownik: ", user_id, "\n",
        "Klucz prywatny: ", private_path, "\n",
        "Klucz publiczny: ", public_path, "\n\n",
        "Zachowaj kopię zapasową klucza prywatnego w bezpiecznym miejscu."
      ))
      
      refresh_user_choices()
      
    }, error = function(e) {
      key_status(paste("Błąd:", conditionMessage(e)))
    })
  })
  
  output$key_result <- renderText(key_status())
  
  # ----------------------------------------------------------
  # TAB 2: Szyfrowanie wiadomości
  # ----------------------------------------------------------
  
  observeEvent(input$encrypt_message, {
    tryCatch({
      sender_id <- input$enc_sender
      recipient_id <- input$enc_recipient
      message_id <- input$enc_message_id
      message <- input$enc_message
      
      if (!valid_id(sender_id) ||
          !valid_id(recipient_id) ||
          !valid_id(message_id)) {
        stop("Nieprawidłowy identyfikator nadawcy, odbiorcy lub wiadomości.")
      }
      
      if (is.null(message) || !nzchar(message)) {
        stop("Wiadomość nie może być pusta.")
      }
      
      sender_key_path <- file.path(
        private_keys_dir, paste0(sender_id, "_key.bin")
      )
      
      recipient_pubkey_path <- file.path(
        public_keys_dir, paste0(recipient_id, "_pubkey.bin")
      )
      
      message_path <- file.path(
        messages_dir, paste0(message_id, ".bin")
      )
      
      nonce_path <- file.path(
        messages_dir, paste0(message_id, "_nonce.bin")
      )
      
      if (file.exists(message_path) || file.exists(nonce_path)) {
        stop(
          "Wiadomość o tym identyfikatorze już istnieje. ",
          "Wybierz inny identyfikator."
        )
      }
      
      sender_key <- read_raw_file(sender_key_path)
      recipient_pubkey <- read_raw_file(recipient_pubkey_path)
      
      msg <- charToRaw(enc2utf8(message))
      
      ciphertext <- sodium::auth_encrypt(
        msg,
        sender_key,
        recipient_pubkey
      )
      
      nonce <- attr(ciphertext, "nonce")
      
      if (is.null(nonce) || length(nonce) == 0) {
        stop("Biblioteka sodium nie zwróciła nonce.")
      }
      
      temp_cipher <- tempfile(tmpdir = messages_dir)
      temp_nonce <- tempfile(tmpdir = messages_dir)
      
      on.exit(unlink(c(temp_cipher, temp_nonce)), add = TRUE)
      
      writeBin(as.raw(ciphertext), temp_cipher)
      writeBin(as.raw(nonce), temp_nonce)
      
      if (!file.rename(temp_cipher, message_path)) {
        stop("Nie udało się zapisać szyfrogramu.")
      }
      
      if (!file.rename(temp_nonce, nonce_path)) {
        unlink(message_path)
        stop("Nie udało się zapisać nonce.")
      }
      
      enc_status(paste0(
        "Wiadomość zaszyfrowana.\n",
        "Nadawca: ", sender_id, "\n",
        "Odbiorca: ", recipient_id, "\n",
        "Identyfikator: ", message_id, "\n",
        "Szyfrogram: ", message_path, "\n",
        "Nonce: ", nonce_path
      ))
      
      refresh_message_choices()
      
    }, error = function(e) {
      enc_status(paste("Błąd:", conditionMessage(e)))
    })
  })
  
  output$encrypt_result <- renderText(enc_status())
  
  # ----------------------------------------------------------
  # TAB 3: Odszyfrowywanie wiadomości
  # ----------------------------------------------------------
  
  observeEvent(input$decrypt_message, {
    tryCatch({
      sender_id <- input$dec_sender
      recipient_id <- input$dec_recipient
      message_id <- input$dec_message_id
      
      if (!valid_id(sender_id) ||
          !valid_id(recipient_id) ||
          !valid_id(message_id)) {
        stop("Wybierz prawidłowego nadawcę, odbiorcę i wiadomość.")
      }
      
      sender_pubkey_path <- file.path(
        public_keys_dir, paste0(sender_id, "_pubkey.bin")
      )
      
      recipient_key_path <- file.path(
        private_keys_dir, paste0(recipient_id, "_key.bin")
      )
      
      message_path <- file.path(
        messages_dir, paste0(message_id, ".bin")
      )
      
      nonce_path <- file.path(
        messages_dir, paste0(message_id, "_nonce.bin")
      )
      
      recipient_key <- read_raw_file(recipient_key_path)
      sender_pubkey <- read_raw_file(sender_pubkey_path)
      ciphertext <- read_raw_file(message_path)
      nonce <- read_raw_file(nonce_path)
      
      decrypted <- sodium::auth_decrypt(
        ciphertext,
        recipient_key,
        sender_pubkey,
        nonce
      )
      
      # Konwersja bajtów UTF-8 z zachowaniem polskich znaków.
      decrypted_text <- rawToChar(decrypted)
      Encoding(decrypted_text) <- "UTF-8"
      
      updateTextAreaInput(
        session,
        "decrypted_text",
        value = decrypted_text
      )
      
      dec_status(paste0(
        "Wiadomość poprawnie odszyfrowana i uwierzytelniona.\n",
        "Nadawca: ", sender_id, "\n",
        "Odbiorca: ", recipient_id, "\n",
        "Identyfikator: ", message_id
      ))
      
    }, error = function(e) {
      updateTextAreaInput(
        session, "decrypted_text", value = ""
      )
      
      dec_status(paste(
        "Nie udało się odszyfrować wiadomości:",
        conditionMessage(e)
      ))
    })
  })
  
  output$decrypt_result <- renderText(dec_status())
  
  # ----------------------------------------------------------
  # TAB 4: Git
  # ----------------------------------------------------------
  
  # Wszystkie polecenia Git wykonujemy bezpośrednio przez
  # system2(), bez składania poleceń powłoki z danych formularza.
  
  run_git <- function(args) {
    output_lines <- suppressWarnings(
      system2(
        "git",
        args = args,
        stdout = TRUE,
        stderr = TRUE
      )
    )
    
    status <- attr(output_lines, "status")
    if (is.null(status)) status <- 0L
    
    list(
      status = status,
      output = paste(output_lines, collapse = "\n")
    )
  }
  
  observeEvent(input$git_status, {
    tryCatch({
      result <- run_git(c("status", "--short", "--branch"))
      
      if (result$status != 0) {
        stop(result$output)
      }
      
      git_status_text(paste(
        "Status repozytorium:\n",
        result$output,
        sep = ""
      ))
      
    }, error = function(e) {
      git_status_text(paste("Błąd Git:", conditionMessage(e)))
    })
  })
  
  observeEvent(input$git_sync, {
    tryCatch({
      user_name <- input$git_user_name
      user_email <- input$git_user_email
      
      if (!isTRUE(input$git_confirm)) {
        stop("Potwierdź, że sprawdziłeś pliki przeznaczone do publikacji.")
      }
      
      if (is.null(user_name) || !nzchar(trimws(user_name)) ||
          is.null(user_email) || !nzchar(trimws(user_email))) {
        stop("Podaj nazwę użytkownika Git i adres e-mail.")
      }
      
      if (!grepl("^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$",
                 user_email)) {
        stop("Podaj poprawny adres e-mail.")
      }
      
      # Sprawdź, czy katalog roboczy jest repozytorium.
      result <- run_git(c("rev-parse", "--is-inside-work-tree"))
      if (result$status != 0) {
        stop("Bieżący katalog nie jest repozytorium Git.")
      }
      
      # Konfiguracja lokalna repozytorium, nie globalna.
      for (setting in list(
        c("user.name", user_name),
        c("user.email", user_email)
      )) {
        result <- run_git(c("config", "--local", setting[1], setting[2]))
        if (result$status != 0) {
          stop(result$output)
        }
      }
      
      # Pobieranie zmian ze zdalnego repozytorium.
      result <- run_git(c("pull", "--rebase"))
      if (result$status != 0) {
        stop(paste("git pull --rebase nie powiódł się:", result$output))
      }
      
      # Dodajemy wyłącznie jawnie wskazane, publikowalne pliki.
      # Nigdy nie wykonujemy tutaj git add .
      result <- run_git(c(
        "add", "--",
        "app.R",
        ".gitignore",
        "public/keys",
        "public/messages"
      ))
      
      if (result$status != 0) {
        stop(result$output)
      }
      
      # Sprawdź, czy jest co commitować.
      result <- run_git(c("diff", "--cached", "--quiet"))
      
      if (result$status == 0) {
        git_status_text(paste(
          "Synchronizacja zakończona.",
          "Brak nowych zmian do zatwierdzenia.",
          sep = "\n"
        ))
        return()
      }
      
      if (result$status != 1) {
        stop("Nie udało się sprawdzić zmian w indeksie Git.")
      }
      
      result <- run_git(c(
        "commit", "-m", "Aktualizacja aplikacji"
      ))
      
      if (result$status != 0) {
        stop(paste("Commit nie powiódł się:", result$output))
      }
      
      result <- run_git(c("push"))
      
      if (result$status != 0) {
        stop(paste(
          "Commit został utworzony, ale push się nie powiódł:",
          result$output
        ))
      }
      
      git_status_text(paste(
        "Synchronizacja zakończona pomyślnie.",
        result$output,
        sep = "\n"
      ))
      
    }, error = function(e) {
      git_status_text(paste(
        "Błąd synchronizacji:",
        conditionMessage(e)
      ))
    })
  })
  
  output$git_result <- renderText(git_status_text())
}

shinyApp(ui = ui, server = server)
