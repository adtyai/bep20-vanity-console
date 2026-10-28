package logx

import "log"

func Event(event, rule string, id int64, count uint64, errorType string) {
	log.Printf("event=%s rule=%s id=%d count=%d error_type=%s", cleanEvent(event), cleanRule(rule), id, count, cleanError(errorType))
}

func cleanEvent(s string) string {
	switch s {
	case "hit", "error", "delete", "reveal", "clear":
		return s
	default:
		return "-"
	}
}

func cleanRule(s string) string {
	switch s {
	case "8A", "9A", "1-8", "1-9":
		return s
	default:
		return "-"
	}
}

func cleanError(s string) string {
	if s == "" {
		return "-"
	}
	if len(s) > 32 {
		return "-"
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '_' && (c < 'a' || c > 'z') {
			return "-"
		}
	}
	return s
}
