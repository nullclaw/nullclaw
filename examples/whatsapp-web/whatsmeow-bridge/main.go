package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mdp/qrterminal/v3"
	"go.mau.fi/whatsmeow"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	"go.mau.fi/whatsmeow/store/sqlstore"
	waTypes "go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"

	_ "github.com/mattn/go-sqlite3"
)

type bridgeMessage struct {
	ID      string `json:"id"`
	From    string `json:"from"`
	ChatID  string `json:"chat_id"`
	GroupID string `json:"group_id,omitempty"`
	Text    string `json:"text"`
	IsGroup bool   `json:"is_group"`
	TS      int64  `json:"timestamp"`
}

type pollRequest struct {
	AccountID string `json:"account_id"`
	Cursor    string `json:"cursor"`
}

type pollResponse struct {
	NextCursor string          `json:"next_cursor"`
	Messages   []bridgeMessage `json:"messages"`
}

type sendRequest struct {
	AccountID string `json:"account_id"`
	To        string `json:"to"`
	Text      string `json:"text"`
}

type bridgeState struct {
	mu sync.Mutex

	accountID string
	queue     []bridgeMessage

	// message IDs created by this bridge via /send, used to avoid echo loops when fromMe is allowed.
	sentByBridge map[string]time.Time

	allowFromMe bool

	client *whatsmeow.Client
}

func normalizePhone(raw string) string {
	b := strings.Builder{}
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func extractText(msg *waProto.Message) string {
	if msg == nil {
		return ""
	}
	if s := msg.GetConversation(); s != "" {
		return s
	}
	if et := msg.GetExtendedTextMessage(); et != nil {
		return et.GetText()
	}
	if im := msg.GetImageMessage(); im != nil {
		return im.GetCaption()
	}
	if vm := msg.GetVideoMessage(); vm != nil {
		return vm.GetCaption()
	}
	return ""
}

func (s *bridgeState) pruneSent(now time.Time) {
	cutoff := now.Add(-10 * time.Minute)
	for id, ts := range s.sentByBridge {
		if ts.Before(cutoff) {
			delete(s.sentByBridge, id)
		}
	}
}

func (s *bridgeState) isOwnOutgoing(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneSent(time.Now())
	_, ok := s.sentByBridge[id]
	return ok
}

func (s *bridgeState) rememberSent(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sentByBridge[id] = time.Now()
}

func (s *bridgeState) enqueue(msg bridgeMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = append(s.queue, msg)
}

func (s *bridgeState) dequeueFromCursor(cursor string) pollResponse {
	s.mu.Lock()
	defer s.mu.Unlock()

	start := 0
	if cursor != "" {
		if _, err := fmt.Sscanf(cursor, "%d", &start); err != nil {
			start = 0
		}
	}
	if start < 0 {
		start = 0
	}
	if start > len(s.queue) {
		start = len(s.queue)
	}

	out := make([]bridgeMessage, len(s.queue[start:]))
	copy(out, s.queue[start:])

	return pollResponse{
		NextCursor: fmt.Sprintf("%d", len(s.queue)),
		Messages:   out,
	}
}

func parseTargetJID(raw string) (waTypes.JID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return waTypes.JID{}, errors.New("empty target")
	}

	if strings.Contains(raw, "@") {
		jid, err := waTypes.ParseJID(raw)
		if err != nil {
			return waTypes.JID{}, err
		}
		return jid, nil
	}

	if strings.Contains(raw, "-") {
		return waTypes.NewJID(raw, waTypes.GroupServer), nil
	}

	phone := normalizePhone(raw)
	if phone == "" {
		return waTypes.JID{}, errors.New("invalid phone target")
	}
	return waTypes.NewJID(phone, waTypes.DefaultUserServer), nil
}

func main() {
	accountID := os.Getenv("NULLCLAW_ACCOUNT_ID")
	if accountID == "" {
		accountID = "default"
	}
	addr := os.Getenv("NULLCLAW_BRIDGE_ADDR")
	if addr == "" {
		addr = "127.0.0.1:3301"
	}
	allowFromMe := os.Getenv("NULLCLAW_WHATSAPP_WEB_ALLOW_FROM_ME") == "1"

	dbPath := os.Getenv("NULLCLAW_WHATSMEOW_DB")
	if dbPath == "" {
		dbPath = "/tmp/nullclaw-whatsmeow.db"
	}

	logger := waLog.Stdout("whatsmeow", "INFO", true)
	container, err := sqlstore.New(context.Background(), "sqlite3", "file:"+dbPath+"?_foreign_keys=on", logger)
	if err != nil {
		log.Fatalf("sqlstore init failed: %v", err)
	}

	device, err := container.GetFirstDevice(context.Background())
	if err != nil {
		log.Fatalf("device load failed: %v", err)
	}

	client := whatsmeow.NewClient(device, logger)

	state := &bridgeState{
		accountID:    accountID,
		queue:        make([]bridgeMessage, 0, 256),
		sentByBridge: make(map[string]time.Time),
		allowFromMe:  allowFromMe,
		client:       client,
	}

	client.AddEventHandler(func(evt any) {
		switch v := evt.(type) {
		case *events.Message:
			text := strings.TrimSpace(extractText(v.Message))
			if text == "" {
				return
			}

			msgID := v.Info.ID
			fromMe := v.Info.IsFromMe
			if fromMe {
				if state.isOwnOutgoing(msgID) {
					return
				}
				if !state.allowFromMe {
					return
				}
			}

			from := v.Info.Sender.User
			if from == "" {
				from = v.Info.Sender.String()
			}

			chat := v.Info.Chat.String()
			isGroup := v.Info.IsGroup
			groupID := ""
			if isGroup {
				groupID = v.Info.Chat.User
			}

			state.enqueue(bridgeMessage{
				ID:      msgID,
				From:    from,
				ChatID:  chat,
				GroupID: groupID,
				Text:    text,
				IsGroup: isGroup,
				TS:      v.Info.Timestamp.Unix(),
			})
		}
	})

	if client.Store.ID == nil {
		qrChan, _ := client.GetQRChannel(context.Background())
		if err := client.Connect(); err != nil {
			log.Fatalf("connect failed: %v", err)
		}
		for evt := range qrChan {
			switch evt.Event {
			case "code":
				fmt.Println("\nScan this QR with WhatsApp (Linked Devices):")
				qrterminal.GenerateHalfBlock(evt.Code, qrterminal.L, os.Stdout)
			case "success":
				log.Println("whatsapp session linked successfully")
			case "timeout":
				log.Println("qr timeout; restart bridge to generate a new code")
			case "error":
				log.Printf("qr error: %s", evt.Error)
			}
		}
	} else {
		if err := client.Connect(); err != nil {
			log.Fatalf("connect failed: %v", err)
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":        true,
			"connected": client.IsConnected(),
			"logged_in": client.IsLoggedIn(),
		})
	})

	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req pollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if req.AccountID != "" && req.AccountID != state.accountID {
			http.Error(w, "unknown account", http.StatusBadRequest)
			return
		}
		res := state.dequeueFromCursor(req.Cursor)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	})

	mux.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req sendRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Text) == "" {
			http.Error(w, "text is required", http.StatusBadRequest)
			return
		}
		if req.AccountID != "" && req.AccountID != state.accountID {
			http.Error(w, "unknown account", http.StatusBadRequest)
			return
		}

		jid, err := parseTargetJID(req.To)
		if err != nil {
			http.Error(w, "invalid target: "+err.Error(), http.StatusBadRequest)
			return
		}

		sent, err := state.client.SendMessage(context.Background(), jid, &waProto.Message{
			Conversation: proto.String(req.Text),
		})
		if err != nil {
			http.Error(w, "send failed: "+err.Error(), http.StatusBadGateway)
			return
		}

		state.rememberSent(sent.ID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"id": sent.ID,
		})
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
	}

	log.Printf("whatsmeow bridge listening on http://%s (account_id=%s, allow_from_me=%v)", addr, accountID, allowFromMe)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("http server failed: %v", err)
	}
}
