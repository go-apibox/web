package web

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/dchest/captcha"
	"github.com/gorilla/mux"
	"gopkg.in/flosch/pongo2.v3"
)

var spiderRe *regexp.Regexp

func init() {
	spiderRe = regexp.MustCompile(`(?i)qihoobot|Baiduspider|Googlebot|Googlebot-Mobile|Googlebot-Image|Mediapartners-Google|Adsbot-Google|Feedfetcher-Google|Yahoo! Slurp|YoudaoBot|Sosospider|Sogou spider|Sogou web spider|MSNBot|ia_archiver|Tomato Bot`)
}

func (web *Web) NewPageFunc(page *Page) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 禁止搜索引擎收录
		if page.disallowSpiders {
			if spiderRe.MatchString(r.UserAgent()) {
				http.Error(w, "403 spiders forbidden", http.StatusForbidden)
				return
			}
		}

		// 每次都重新新建ctx对象，避免并发写入map
		ctx := pongo2.Context{}

		// 注入数据
		// 全局
		for k, v := range web.injectData {
			ctx[k] = v
		}
		// include数据
		for k, v := range web.injectIncludeData {
			dataFilePath := filepath.Join(web.webRoot, v)
			dataBytes, err := ioutil.ReadFile(dataFilePath)
			if err == nil {
				ctx[k] = string(dataBytes)
			}
		}

		vars := mux.Vars(r)

		if web.debug {
			var vstr string
			if len(vars) > 0 {
				vstr = fmt.Sprint(vars)
			}
			logger.Debug("%s %s %s", r.Method, r.RequestURI, vstr)
		}

		// 查找是否在 excepts 列表中
		exceptFound := true
		if len(page.excepts) > 0 {
			for condKey, condVals := range page.excepts {
				if val, ok := vars[condKey]; ok {
					condMatched := false
					for _, condVal := range condVals {
						if condVal == val {
							condMatched = true
							break
						}
					}
					if !condMatched {
						exceptFound = false
						break
					}
				} else {
					// 输入参数不满足条件
					exceptFound = false
					break
				}
			}
		} else {
			exceptFound = false
		}

		isPublic := false
		if page.public && !exceptFound || !page.public && exceptFound {
			isPublic = true
		}

		if !isPublic {
			// 检查登录
			s, err := web.GetSessionStore(page.authSessionName).Get(r, page.authSessionName)
			if err != nil {
				logger.Error(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if authed, err := s.GetBool(page.authSessionKey); err != nil || !authed {
				if page.unauthedRedirect && page.loginUrl != "" {
					if page.unauthedRedirectMethod == "javascript" {
						if strings.Contains(page.loginUrl, "{$FROM_URL$}") {
							loginUrl := strings.Replace(page.loginUrl, "{$FROM_URL$}", "", 1)
							w.Write([]byte("<script>location.href='" + loginUrl + "'+encodeURIComponent(location.pathname+location.search+location.hash);</script>"))
						} else {
							w.Write([]byte("<script>location.href='" + page.loginUrl + "';</script>"))
						}
					} else {
						loginUrl := strings.Replace(page.loginUrl, "{$FROM_URL$}", url.QueryEscape(r.RequestURI), 1)
						http.Redirect(w, r, loginUrl, 302)
					}
				} else {
					http.Error(w, "401 page not authorized", http.StatusUnauthorized)
				}
				return
			}
		}

		// 页面级数据
		// 变量值中含有模板变量的，暂不解析，待注入所有变量值后再解析
		varPageData := make(map[string]string)
		for k, v := range page.data {
			if vv, ok := v.(string); ok {
				captchaPrefix := "@captcha"
				if strings.Index(vv, "{$") != -1 {
					varPageData[k] = vv
				} else if strings.HasPrefix(vv, captchaPrefix) {
					// 产生随机数
					length := 6
					if vv != captchaPrefix {
						l, err := strconv.Atoi(vv[len(captchaPrefix)+1:])
						if err == nil {
							length = l
						}
					}
					ctx[k] = captcha.NewLen(length)
				} else {
					ctx[k] = v
				}
			} else {
				ctx[k] = v
			}
		}

		// 注入 url 变量
		for k, v := range vars {
			ctx[k] = v
		}

		// 注入 session
		web.sessionStoreMutex.RLock()
		for k, sessionName := range web.injectSessionMap {
			if s, err := web.GetSessionStore(sessionName).Get(r, sessionName); err == nil {
				ctx[k] = s.Values
			}
		}
		web.sessionStoreMutex.RUnlock()

		// 分析未分析完的变量
		for k, v := range varPageData {
			if t, err := pongo2.FromString(v); err != nil {
				logger.Error(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			} else {
				if v, err = t.Execute(ctx); err != nil {
					logger.Error(err.Error())
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			ctx[k] = v
		}

		tmplPath := page.template
		if strings.Index(tmplPath, "{$") != -1 {
			if t, err := pongo2.FromString(tmplPath); err != nil {
				logger.Error(err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			} else {
				if tmplPath, err = t.Execute(ctx); err != nil {
					logger.Error(err.Error())
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}

		tmplPath = filepath.Join(web.webRoot, tmplPath)
		if web.debug {
			logger.Debug("  => file: %s", tmplPath)
		}

		tmpl, err := pongo2.FromFile(tmplPath)
		if err != nil {
			logger.Error(err.Error())
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if len(page.headers) > 0 {
			for k, v := range page.headers {
				w.Header().Set(k, v)
			}
		}

		if err := tmpl.ExecuteWriter(ctx, w); err != nil {
			logger.Error(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
