package web

import (
	"net/http"
	"strings"
)

func (web *Web) NewRestartFunc(page *Page) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if web.debug {
			logger.Debug("%s %s", r.Method, r.RequestURI)
		}

		// csrf验证
		var sessionCsrfKey, httpCsrfHeader string
		t, has := page.data["session_csrf_token"]
		if !has {
			sessionCsrfKey = "default.csrf_token"
		} else {
			var ok bool
			sessionCsrfKey, ok = t.(string)
			if !ok || sessionCsrfKey == "" {
				sessionCsrfKey = "default.csrf_token"
			}
		}
		parts := strings.SplitN(sessionCsrfKey, ".", 2)
		if len(parts) != 2 {
			parts = []string{"default", parts[0]}
		}
		csrfSessionName, csrfSessionKey := parts[0], parts[1]

		t, has = page.data["http_csrf_header"]
		if !has {
			httpCsrfHeader = "X-CSRF-TOKEN"
		} else {
			var ok bool
			httpCsrfHeader, ok = t.(string)
			if !ok || httpCsrfHeader == "" {
				httpCsrfHeader = "X-CSRF-TOKEN"
			}
		}

		s, err := web.GetSessionStore(csrfSessionName).Get(r, csrfSessionName)
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var msg, apiLang string
		apiLang = r.Form.Get("api_lang")

		headerCsrf := r.Header.Get(httpCsrfHeader)
		sessionCsrf, _ := s.GetString(csrfSessionKey)
		if headerCsrf == "" || headerCsrf != sessionCsrf {
			if apiLang == "en_us" {
				msg = "CSRF token error!"
			} else {
				msg = "CSRF验证失败！"
			}
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		if apiLang == "en_us" {
			msg = "Restart command sent!"
		} else {
			msg = "重启指令已发送！"
		}
		w.Write([]byte(msg))

		// 重启
		go web.RestartFunc()
	}
}
