package main

import (
	"MatrixBot/matrix"
	"crypto/rand"
	"database/sql"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var homeserver string
var displayName string
var username string
var password string
var pickleKey []byte
var recoveryKey string

var db *sql.DB

func main() {
	defer db.Close()

	gracefulShutdown := make(chan os.Signal, 1)
	signal.Notify(gracefulShutdown, syscall.SIGINT, syscall.SIGTERM)

	shouldStore := true

	res, err := db.Query("SELECT accessToken, deviceId, userId, pickleKey FROM credentials")
	if err != nil {
		panic(err)
	}
	defer res.Close()

	var accessToken string
	var deviceId string
	var userId string

	if res.Next() {
		shouldStore = false
		err = res.Scan(&accessToken, &deviceId, &userId, &pickleKey)
		if err != nil {
			panic(err)
		}
	}

	var bot *matrix.Bot
	if accessToken != "" && deviceId != "" && userId != "" {
		bot, err = matrix.NewBotWithAccessTokenCredentials(homeserver, displayName, accessToken, userId, deviceId)
	} else {
		bot, err = matrix.NewBotWithUsernameAndPassword(homeserver, displayName, username, password)
	}
	if err != nil {
		panic(err)
	}

	if pickleKey == nil {
		pickleKey = make([]byte, 32)
		_, err = rand.Read(pickleKey)
		if err != nil {
			panic(err)
		}
	}

	bot.EnableEncryption(pickleKey)
	if recoveryKey != "" {
		bot.EnableSessionVerification(recoveryKey)
	}
	err = bot.Init()
	if err != nil {
		panic(err)
	}

	if shouldStore {
		_, err = db.Exec("INSERT INTO credentials VALUES (?, ?, ?, ?)", bot.AccessToken, bot.DeviceId, bot.UserId, pickleKey)
		if err != nil {
			panic(err)
		}
	}

	go func() {
		errChan := bot.Run()
		err = <-errChan
		if err != nil {
			panic(err)
		}
	}()

	log.Println("Bot is running. Press Ctrl+C to exit.")
	<-gracefulShutdown
	log.Println("Bot is shutting down...")
}

func init() {
	var ok bool
	var err error

	homeserver, ok = os.LookupEnv("BOT_HOMESERVER")
	if !ok {
		panic("missing BOT_HOMESERVER env var")
	}

	username, ok = os.LookupEnv("BOT_USERNAME")
	if !ok {
		panic("missing BOT_USERNAME env var")
	}

	password, ok = os.LookupEnv("BOT_PASSWORD")
	if !ok {
		panic("missing BOT_PASSWORD env var")
	}

	displayName, ok = os.LookupEnv("BOT_DISPLAY_NAME")
	if !ok {
		displayName = username
	}

	recoveryKey, ok = os.LookupEnv("BOT_RECOVERY_KEY")
	if !ok {
		log.Println("Warning: missing BOT_RECOVERY_KEY env var. Session verification will be disabled.")
	}

	db, err = sql.Open("sqlite3", "matrix_bot_creds.db")
	if err != nil {
		panic(err)
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS credentials (accessToken TEXT, deviceId TEXT, userId TEXT, pickleKey BLOB)")
	if err != nil {
		panic(err)
	}
}
