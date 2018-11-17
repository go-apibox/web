package web

import (
	"net/http"
	"strconv"

	"github.com/dchest/captcha"
)

func (web *Web) NewCaptchaFunc(page *Page) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if web.debug {
			logger.Debug("%s %s", r.Method, r.RequestURI)
		}

		id := r.FormValue("id")
		if id == "" {
			http.NotFound(w, r)
			return
		}
		if r.FormValue("reload") != "" {
			captcha.Reload(id)
		}

		imgWidth := 180
		imgHeight := 60

		if w, ok := page.data["@width"]; ok {
			imgWidth = w.(int)
		}
		if h, ok := page.data["@height"]; ok {
			imgHeight = h.(int)
		}
		if width := r.Form.Get("width"); width != "" {
			if w, err := strconv.Atoi(width); err == nil && w < 300 {
				imgWidth = w
			}
		}
		if height := r.Form.Get("height"); height != "" {
			if h, err := strconv.Atoi(height); err == nil && h < 300 {
				imgHeight = h
			}
		}

		if captcha.WriteImage(w, id, imgWidth, imgHeight) == captcha.ErrNotFound {
			http.NotFound(w, r)
			return
		}
	}
}
