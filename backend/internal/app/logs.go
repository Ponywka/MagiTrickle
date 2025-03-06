package app

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// LogEvent описывает структуру лог-события для API-подписок
type LogEvent struct {
	Level   string                 `json:"level"`
	Message string                 `json:"message"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
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

// notifySubscribers рассылает лог-событие всем активным подпискам
func notifySubscribers(ev LogEvent) {
	globalHub.mu.RLock()
	defer globalHub.mu.RUnlock()
	for sub := range globalHub.subscribers {
		select {
		case sub.ch <- ev:
		default:
			// если заполнен буфер, событие пропускается
		}
	}
}

// splitWriter – собственный writer, который в методе Write выполняет два действия:
//  1. Интерцептирует исходное JSON-сообщение (которое генерирует zerolog),
//     извлекает level, message и дополнительные поля, и уведомляет API-подписчиков.
//  2. Передаёт исходное сообщение в ConsoleWriter для pretty‑вывода в консоль.
type splitWriter struct {
	console zerolog.ConsoleWriter
}

func (sw *splitWriter) Write(p []byte) (n int, err error) {
	var level, msg string
	fields := make(map[string]interface{})
	var data map[string]interface{}
	if err := json.Unmarshal(p, &data); err != nil {
		// Если не удалось распарсить, считаем, что это простой текст.
		level = "info"
		msg = string(p)
	} else {
		if l, ok := data["level"].(string); ok {
			level = l
		}
		if m, ok := data["message"].(string); ok {
			msg = m
		}
		// Копируем все дополнительные поля, кроме level и message
		for k, v := range data {
			if k == "level" || k == "message" {
				continue
			}
			fields[k] = v
		}
	}
	// Отправляем подписчикам полное событие в виде JSON
	notifySubscribers(LogEvent{
		Level:   level,
		Message: msg,
		Fields:  fields,
	})

	return sw.console.Write(p)
}

// SelectLogLevel выбирает уровень логирования по строке и устанавливает его глобально
func SelectLogLevel(logLevel string) {
	lvl, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(lvl)
}

// StartLogs настраивает глобальный логгер
func StartLogs() {

	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout}
	sw := &splitWriter{console: consoleWriter}

	logger := zerolog.New(sw).With().Timestamp().Logger()
	log.Logger = logger
}
