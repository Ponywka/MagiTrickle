package app

import (
	"encoding/json"
	"io"
	"os"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// LogEvent описывает структуру лог-события для API-подписок
type LogEvent struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// LogSubscription представляет подписку на поток логов
type LogSubscription struct {
	ch chan LogEvent
}

// Out возвращает канал для чтения логов
func (s *LogSubscription) Out() <-chan LogEvent { return s.ch }

// Close закрывает канал подписки
func (s *LogSubscription) Close() { close(s.ch) }

// loggingHub хранит активные подписки
type loggingHub struct {
	mu          sync.RWMutex
	subscribers map[*LogSubscription]struct{}
}

var globalHub = &loggingHub{
	subscribers: make(map[*LogSubscription]struct{}),
}

// SubscribeLogs создаёт новую подписку с буфером 100 сообщений
func SubscribeLogs() *LogSubscription {
	sub := &LogSubscription{ch: make(chan LogEvent, 100)}
	globalHub.mu.Lock()
	globalHub.subscribers[sub] = struct{}{}
	globalHub.mu.Unlock()
	return sub
}

// UnsubscribeLogs удаляет подписку и закрывает её канал
func UnsubscribeLogs(sub *LogSubscription) {
	globalHub.mu.Lock()
	delete(globalHub.subscribers, sub)
	globalHub.mu.Unlock()
	sub.Close()
}

// notifySubscribers рассылает лог-событие всем активным подпискам; если у подписчика заполнен буфер, событие пропускается
func notifySubscribers(ev LogEvent) {
	globalHub.mu.RLock()
	defer globalHub.mu.RUnlock()
	for sub := range globalHub.subscribers {
		select {
		case sub.ch <- ev:
		default:
			// событие пропускается
		}
	}
}

type dualWriter struct {
	writer io.Writer
}

func (dw *dualWriter) Write(p []byte) (n int, err error) {
	var level, msg string

	var data map[string]interface{}
	if err := json.Unmarshal(p, &data); err != nil {
		level = "info"
		msg = string(p)
	} else {
		if l, ok := data["level"].(string); ok {
			level = l
		}
		if m, ok := data["message"].(string); ok {
			msg = m
		}
	}

	notifySubscribers(LogEvent{
		Level:   level,
		Message: msg,
	})

	return dw.writer.Write(p)
}

// SetupLogs настраивает глобальный логгер
func SetupLogs(logLevel string) {
	lvl, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)

	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout}

	dw := &dualWriter{writer: consoleWriter}

	logger := zerolog.New(dw).With().Timestamp().Logger()
	log.Logger = logger
}
