package matrix

import (
	"context"
	"errors"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"sync"
)

type Bot struct {
	DisplayName string
	Homeserver  string

	Username string
	password string

	AccessToken string
	UserId      id.UserID
	DeviceId    id.DeviceID

	matrix *mautrix.Client
	ctx    context.Context

	DbPath              string
	encryptionPickleKey *[]byte
	recoveryKey         *string
	syncer              *mautrix.DefaultSyncer
	cryptoHelper        *cryptohelper.CryptoHelper

	OnMessage mautrix.EventHandler
}

func NewBot(homeserver, displayName string) (*Bot, error) {
	client, err := mautrix.NewClient(homeserver, "", "")
	if err != nil {
		return nil, err
	}

	return &Bot{
		DisplayName: displayName,
		Homeserver:  homeserver,
		matrix:      client,
		DbPath:      "matrix_bot.db",
	}, nil
}

func NewBotWithUsernameAndPassword(homeserver, displayName, username, password string) (*Bot, error) {
	bot, err := NewBot(homeserver, displayName)
	if err != nil {
		return nil, err
	}

	bot.SetUsernamePassword(username, password)

	return bot, nil
}

func NewBotWithAccessTokenCredentials(homeserver, displayName, accessToken, userId, deviceId string) (*Bot, error) {
	bot, err := NewBot(homeserver, displayName)
	if err != nil {
		return nil, err
	}
	bot.SetAccessTokenCredentials(accessToken, userId, deviceId)

	return bot, nil
}

func (receiver *Bot) SetContext(ctx context.Context) {
	receiver.ctx = ctx
}

func (receiver *Bot) Init() (err error) {
	if receiver.Username != "" && receiver.password != "" && (receiver.AccessToken == "" || receiver.UserId == "" || receiver.DeviceId == "") {
		err = receiver.login()
		if err != nil {
			return
		}
	}

	if receiver.AccessToken == "" || receiver.UserId == "" || receiver.DeviceId == "" {
		err = errors.New("either username and password or access token and user id and device id must be set")
		return
	}

	receiver.syncer = mautrix.NewDefaultSyncer()
	receiver.matrix.Syncer = receiver.syncer

	if receiver.encryptionPickleKey != nil {
		err = receiver.initializeEncryption()
		if err != nil {
			return
		}
	}

	err = receiver.matrix.SetDisplayName(receiver.getCtx(), receiver.DisplayName)
	if err != nil {
		return
	}

	return
}

func (receiver *Bot) RunWithMessageCallback(onMessage mautrix.EventHandler) chan error {
	receiver.OnMessage = onMessage
	return receiver.Run()
}

func (receiver *Bot) Run() chan error {
	readyChan := make(chan bool)

	var once sync.Once
	receiver.syncer.OnSync(func(ctx context.Context, resp *mautrix.RespSync, since string) bool {
		once.Do(func() {
			close(readyChan)

			if receiver.recoveryKey != nil {
				err := receiver.verifySession()
				if err != nil {
					panic(err)
				}
			}
		})

		return true
	})

	if receiver.OnMessage != nil {
		receiver.syncer.OnEventType(event.EventMessage, receiver.OnMessage)
	}

	errChan := make(chan error)
	go func() {
		if err := receiver.matrix.Sync(); err != nil {
			errChan <- err
			close(errChan)
		}
	}()

	return errChan
}

func (receiver *Bot) SetUsernamePassword(username, password string) {
	receiver.Username = username
	receiver.password = password
}

func (receiver *Bot) SetAccessTokenCredentials(accessToken, userId, deviceId string) {
	receiver.AccessToken = accessToken
	receiver.UserId = id.UserID(userId)
	receiver.DeviceId = id.DeviceID(deviceId)

	receiver.matrix.AccessToken = accessToken
	receiver.matrix.UserID = receiver.UserId
	receiver.matrix.DeviceID = receiver.DeviceId
}

func (receiver *Bot) EnableEncryption(pickleKey []byte) {
	receiver.encryptionPickleKey = &pickleKey
}

func (receiver *Bot) EnableSessionVerification(recoveryKey string) {
	receiver.recoveryKey = &recoveryKey
}

func (receiver *Bot) SendMessage(text string, roomID string) error {
	content := event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    text,
	}

	_, err := receiver.matrix.SendMessageEvent(context.Background(), id.RoomID(roomID), event.EventMessage, content)
	if err != nil {
		return err
	}

	return nil
}

func (receiver *Bot) login() error {
	response, err := receiver.matrix.Login(receiver.getCtx(), &mautrix.ReqLogin{
		Type: mautrix.AuthTypePassword,
		Identifier: mautrix.UserIdentifier{
			User: receiver.Username,
			Type: mautrix.IdentifierTypeUser,
		},
		Password:           receiver.password,
		StoreCredentials:   true,
		StoreHomeserverURL: true,
	})
	if err != nil {
		return err
	}

	receiver.AccessToken = response.AccessToken
	receiver.UserId = response.UserID
	receiver.DeviceId = response.DeviceID

	return nil
}

func (receiver *Bot) getCtx() context.Context {
	if receiver.ctx == nil {
		receiver.ctx = context.Background()
	}

	return receiver.ctx
}

func (receiver *Bot) initializeEncryption() error {
	helper, err := cryptohelper.NewCryptoHelper(receiver.matrix, *receiver.encryptionPickleKey, receiver.DbPath)
	if err != nil {
		return err
	}

	err = helper.Init(receiver.getCtx())
	if err != nil {
		return err
	}

	receiver.cryptoHelper = helper
	receiver.matrix.Crypto = receiver.cryptoHelper

	return nil
}

func (receiver *Bot) verifySession() (err error) {
	machine := receiver.cryptoHelper.Machine()
	ctx := receiver.getCtx()

	keyId, keyData, err := machine.SSSS.GetDefaultKeyData(ctx)
	if err != nil {
		return
	}
	key, err := keyData.VerifyRecoveryKey(keyId, *receiver.recoveryKey)
	if err != nil {
		return
	}
	err = machine.FetchCrossSigningKeysFromSSSS(ctx, key)
	if err != nil {
		return
	}
	err = machine.SignOwnDevice(ctx, machine.OwnIdentity())
	if err != nil {
		return
	}
	err = machine.SignOwnMasterKey(ctx)

	return
}
