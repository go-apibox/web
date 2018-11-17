package web

import (
	"net/http"
)

func (web *Web) NewLoginFunc(page *Page) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if web.debug {
			logger.Debug("%s %s", r.Method, r.RequestURI)
		}

		s, err := web.GetSessionStore(page.authSessionName).Get(r, page.authSessionName)
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		s.Set(page.authSessionKey, true)
		for k, v := range page.data {
			if k[0] != '@' {
				s.Set(k, v)
			}
		}
		s.Save(w)

		if jumpTo, ok := page.data["@jump_to"]; ok {
			http.Redirect(w, r, jumpTo.(string), 302)
		} else {
			w.Write([]byte("login ok"))
		}
	}
}

func (web *Web) NewLogoutFunc(page *Page) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if web.debug {
			logger.Debug("%s %s", r.Method, r.RequestURI)
		}

		s, err := web.GetSessionStore(page.authSessionName).Get(r, page.authSessionName)
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.Options.Domain = web.sessionDomain
		s.Destroy(w)

		if jumpTo, ok := page.data["@jump_to"]; ok {
			http.Redirect(w, r, jumpTo.(string), 302)
		} else {
			w.Write([]byte("logout ok"))
		}
	}
}
