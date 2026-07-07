package xraybridge

import (
	"fmt"
	"strings"

	xraylog "github.com/xtls/xray-core/common/log"
)

// InitLogger configures xray-core's internal logger (common/log) so that the
// xray-core leaf packages (transport/VLESS) emit logs to stdout filtered by the
// given minimum severity. It must be called exactly once at server startup —
// the periodic hot-reload sync must not call it again.
//
// xray-core's common/log already installs a stdout handler by default (no
// filtering); calling this replaces it with a severity-filtered handler.
func InitLogger(level string) error {
	sev, err := parseXrayLogLevel(level)
	if err != nil {
		return err
	}
	xraylog.ReplaceWithSeverityLogger(sev)
	return nil
}

// parseXrayLogLevel maps a textual level (shared with logrus vocabulary) to
// xray-core's Severity enum. Higher value = more verbose; msg.Severity <=
// configured level is what gets logged. xray-core has no trace/fatal/panic
// levels, so those collapse onto its nearest coarser level.
func parseXrayLogLevel(s string) (xraylog.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace", "debug":
		return xraylog.Severity_Debug, nil
	case "info":
		return xraylog.Severity_Info, nil
	case "warn", "warning":
		return xraylog.Severity_Warning, nil
	case "error", "fatal", "panic":
		return xraylog.Severity_Error, nil
	case "none":
		return xraylog.Severity_Unknown, nil
	default:
		return xraylog.Severity_Warning, fmt.Errorf("unknown log_level %q", s)
	}
}
