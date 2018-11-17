package web

import (
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	_api "github.com/go-apibox/api"
	"github.com/go-apibox/apiclient"
	"github.com/go-apibox/session"
	"github.com/go-apibox/utils"
	"github.com/dchest/captcha"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/websocket"
)

// 修复HTTP头部中的Content-Type
// 支付宝Notify通知结果头部如：
// Content-Type: application/x-www-form-urlencoded; text/html; charset=utf-8
// 为造成ParseForm()报错：mime: invalid media parameter
func fixHeader(h http.Header) {
	if ct, has := h["Content-Type"]; has && len(ct) > 0 {
		fields := strings.Split(ct[0], ";")
		okFields := []string{}
		if len(fields) > 1 {
			okFields = append(okFields, fields[0])
			for _, field := range fields[1:] {
				// 必须带有=，而且不能包含/
				if strings.IndexByte(field, '=') < 0 {
					continue
				}
				if strings.IndexByte(field, '/') >= 0 {
					continue
				}
				okFields = append(okFields, field)
			}
			h["Content-Type"][0] = strings.Join(okFields, ";")
		}
	}
}

func (web *Web) NewAPIFunc(api *API) http.HandlerFunc {
	// 每个API后端都使用独立的sessionstore
	web.sessionStoreMutex.Lock()
	for _, localCookieName := range api.proxySessionMap {
		if _, exists := web.sessionStoreMap[localCookieName]; exists {
			continue
		}
		store, err := session.NewCookieStore(false, "")
		if err != nil {
			continue
		}
		web.sessionStoreMap[localCookieName] = store
	}
	web.sessionStoreMutex.Unlock()

	if api.proxySessionEnabled {
		// 每天更新一次 cookie key
		go web.updateCookieKeyLoop(api)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "POST" {
			http.Error(w, "Unsupported request method!", http.StatusMethodNotAllowed)
			return
		}
		if web.debug {
			logger.Debug("%s %s", r.Method, r.RequestURI)
		}

		fixHeader(r.Header)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Request parse failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		action := r.Form.Get("api_action")

		// 判断是否要进行验证码检测
		isCaptchaRequiredAction := false
		if api.captchaMatcher.Match(action) {
			isCaptchaRequiredAction = true

			// 检测启动条件
			needCaptcha := false
			captchaConfig := api.captchaConfigs[action]
			if captchaConfig.maxFailCount == 0 {
				needCaptcha = true
			} else {
				// 检查是否超过最大失败次数
				idVal := r.Form.Get(captchaConfig.identifier)
				key := fmt.Sprintf("%s|%s", action, idVal)
				item, has := web.captchaCache.Get(key)
				if has && item.MustInt(0) > captchaConfig.maxFailCount {
					needCaptcha = true
				}
			}

			if needCaptcha {
				id := r.Form.Get("captcha_id")
				code := r.Form.Get("captcha_code")
				if id == "" || code == "" {
					var msg string
					if r.Form.Get("api_lang") == "en_us" {
						msg = "Missing captcha info!"
					} else {
						msg = "缺少验证码信息！"
					}
					errRes := _api.NewError("MissingCaptcha", msg)
					_api.WriteData(w, r, errRes, action, "json", "", r.Form.Get("api_debug"))
					return
				}
				if !captcha.VerifyString(id, code) {
					// 验证失败，刷新验证码
					captcha.Reload(id)

					var msg string
					if r.Form.Get("api_lang") == "en_us" {
						msg = "Captcha verified failed!"
					} else {
						msg = "验证码错误！"
					}
					errRes := _api.NewError("InvalidCaptcha", msg)
					_api.WriteData(w, r, errRes, action, "json", "", r.Form.Get("api_debug"))
					return
				} else {
					// 验证成功，也一样刷新，防止重复利用
					captcha.Reload(id)
				}
			}
		}

		// 代理到后端API
		client := apiclient.NewClient(api.server)
		if api.addr != "" {
			client.GWADDR = api.addr
		}
		if api.signKey != "" {
			client.SignKey = api.signKey
		}
		if api.nonceLength > 0 {
			client.NonceEnabled = true
			client.NonceLength = api.nonceLength
		}
		for k, v := range api.params {
			client.SetDefaultParam(k, v)
		}

		// 判断是否websocket请求
		if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
			var resp *apiclient.Response
			var err error

			// 删除头部cookie，重新构造
			cookies := r.Cookies()
			r.Header.Del("Cookie")

			for _, cookie := range cookies {
				// 删除未在配置中的cookie
				remoteCookieName, exists := api.proxySessionRMap[cookie.Name]
				if !exists {
					continue
				}

				// 名称不同，则需要解密后重新加密
				if remoteCookieName != cookie.Name {
					localSessionStore := web.GetSessionStore(remoteCookieName)

					// 解密cookie
					dst := make(map[interface{}]interface{})
					web.sessionStoreMutex.RLock()
					err := securecookie.DecodeMulti(cookie.Name, cookie.Value, &dst, localSessionStore.Codecs...)
					web.sessionStoreMutex.RUnlock()
					if err != nil {
						// 无法识别，丢弃
						continue
					}
					// 改名后重新加密
					cookie.Name = remoteCookieName
					web.sessionStoreMutex.RLock()
					cookie.Value, err = securecookie.EncodeMulti(cookie.Name, dst, localSessionStore.Codecs...)
					web.sessionStoreMutex.RUnlock()
					if err != nil {
						// 加密失败，丢弃
						continue
					}
				}
				r.Header.Add("Cookie", cookie.String())
			}

			var remoteIp string
			if r.RemoteAddr != "@" {
				remoteIp, _, _ = net.SplitHostPort(r.RemoteAddr)
			} else {
				// unix domain socket
				remoteIp = "@"
			}
			r.Header.Set("X-Real-IP", remoteIp)

			switch r.Method {
			case "GET":
				resp, err = client.Get(action, r.Form, r.Header)
			case "POST":
				// 判断是否上传文件
				isMultiPart := false
				contentType := r.Header.Get("Content-Type")
				if contentType != "" {
					mediaType, _, err := mime.ParseMediaType(contentType)
					if err == nil && strings.HasPrefix(mediaType, "multipart/") {
						isMultiPart = true
					}
				}

				if !isMultiPart {
					resp, err = client.Post(action, r.Form, r.Header)
				} else {
					resp, err = client.Upload(action, r.Form, r.Header, r.Body)
				}
			default:
				return
			}

			if err != nil {
				if resp != nil && resp.Header.Get("X-Allow-Error-Response") == "on" {
					// 返回原始响应内容
					// return resp, nil
				} else {
					logger.Error("Request to api gateway failed: %s", err.Error())
					http.Error(w, "Request to api gateway failed!", http.StatusBadGateway)
					return
				}
			}

			// 解析Cookie，管理session过期
			cookies = resp.Cookies()
			resp.Header.Del("Set-Cookie") // 清除头部重新构造
			for _, cookie := range cookies {
				// 删除未在配置中的cookie
				localCookieName, exists := api.proxySessionMap[cookie.Name]
				if !exists {
					logger.Warning("Cookie name '%s' in api response is not defined, ignored.", cookie.Name)
					continue
				}

				localSessionStore := web.GetSessionStore(localCookieName)

				dst := make(map[interface{}]interface{})
				web.sessionStoreMutex.RLock()
				err := securecookie.DecodeMulti(cookie.Name, cookie.Value, &dst, localSessionStore.Codecs...)
				web.sessionStoreMutex.RUnlock()
				if err != nil {
					if web.debug {
						// 调试模式下，自动重新获取keypair
						logger.Error(
							"Cookie '%s' in api response decode failed: '%s', try update cookie key.",
							cookie.Name, err.Error(),
						)
						web.updateCookieKey(api)
						web.sessionStoreMutex.RLock()
						err := securecookie.DecodeMulti(cookie.Name, cookie.Value, &dst, localSessionStore.Codecs...)
						web.sessionStoreMutex.RUnlock()
						if err != nil {
							// 仍然无法识别，丢弃
							logger.Error(
								"Cookie '%s' in api response decode failed: '%s', ignored.",
								cookie.Name, err.Error(),
							)
							continue
						}
					} else {
						// 无法识别，丢弃
						logger.Error(
							"Cookie '%s' in api response decode failed: '%s', ignored.",
							cookie.Name, err.Error(),
						)
						continue
					}
				}

				// 取出session_id
				sessionId := ""
				for k, v := range dst {
					kk, ok := k.(string)
					if !ok {
						continue
					}
					if kk == "session_id" {
						vv, ok := v.(string)
						if !ok {
							continue
						}
						sessionId = vv
					}
				}
				if sessionId != "" {
					// 更新cache
					web.sessionStoreMutex.RLock()
					localSessionStore.SessionCache.SetIfNotExist(sessionId, true)
					web.sessionStoreMutex.RUnlock()
				}

				// 名称不同，则需要重新加密
				if localCookieName != cookie.Name {
					cookie.Name = localCookieName
					web.sessionStoreMutex.RLock()
					cookie.Value, err = securecookie.EncodeMulti(cookie.Name, dst, localSessionStore.Codecs...)
					web.sessionStoreMutex.RUnlock()
					if err != nil {
						// 加密失败，丢弃
						logger.Error(
							"Cookie '%s' in api response encode failed: '%s', ignored.",
							cookie.Name, err.Error(),
						)
						continue
					}
				}
				resp.Header.Add("Set-Cookie", cookie.String())
			}

			// 原样输出
			header := w.Header()
			for k, v := range resp.Header {
				header[k] = v
			}

			// 操作失败次数计数，用于验证码开启检测
			if isCaptchaRequiredAction {
				if apiResult, err := resp.Result(); err == nil {
					captchaConfig := api.captchaConfigs[action]
					if captchaConfig.maxFailCount > 0 {
						idVal := r.Form.Get(captchaConfig.identifier)
						key := fmt.Sprintf("%s|%s", action, idVal)
						if apiResult.CODE != "ok" {
							// 登录失败，计数加1
							item, has := web.captchaCache.Get(key)
							if !has {
								web.captchaCache.Set(key, 1)
							} else {
								web.captchaCache.Set(key, item.MustInt(0)+1)
							}
						} else {
							// 登录成功，清空计数
							if web.captchaCache.Has(key) {
								web.captchaCache.Set(key, 0)
							}
						}
					}
				}
			}

			w.WriteHeader(resp.StatusCode)

			if isCaptchaRequiredAction {
				// body已被读取
				body, err := resp.String()
				if err != nil {
					logger.Error("API gateway response write failed: %s", err.Error())
					http.Error(w, "API gateway response get failed!", http.StatusInternalServerError)
					return
				}
				_, err = w.Write([]byte(body))
				if err != nil {
					logger.Error("API gateway response write failed: %s", err.Error())
					http.Error(w, "API gateway response write failed!", http.StatusInternalServerError)
					return
				}
			} else {
				// body未被读取
				defer resp.Body.Close()
				_, err = io.Copy(w, resp.Body)
				if err != nil {
					logger.Error("API gateway response write failed: %s", err.Error())
					http.Error(w, "API gateway response write failed!", http.StatusInternalServerError)
					return
				}
			}
		} else {
			// websocket
			_, err := client.Websocket(action, r.Form, r.Header, w, r)
			if err != nil {
				// 非关闭连接错误，均打印日志，连接错误示例：
				// websocket failed: websocket: close 1005
				isCloseError := false
				if _, ok := err.(*websocket.CloseError); ok {
					isCloseError = true
				} else if strings.Contains(err.Error(), "use of closed network connection") {
					// go库net/net.go中获取到的网络错误，如：
					// websocket failed: read tcp 192.168.1.140:8888->192.168.1.52:51058: use of closed network connection
					isCloseError = true
				} else if strings.Contains(err.Error(), "unexpected EOF") {
					// websocket: close 1006 unexpected EOF
					isCloseError = true
				}

				if !isCloseError {
					logger.Error("websocket failed: %s", err.Error())
				}
				return
			}
		}
	}
}

func (web *Web) updateCookieKeyLoop(api *API) {
	for {
		web.updateCookieKey(api)
		time.Sleep(time.Duration(24) * time.Hour)
	}
}

// 更新Cookie密钥，如果失败则不断间隔重试
func (web *Web) updateCookieKey(api *API) {
	for {
		if strings.HasPrefix(api.addr, "/") {
			// unix domain socket
			if !utils.FileExists(api.addr) {
				time.Sleep(time.Second * time.Duration(1))
				continue
			}
		}

		client := apiclient.NewClient(api.server)
		if api.addr != "" {
			client.GWADDR = api.addr
		}
		if api.proxySessionSignKey != "" {
			client.SignKey = api.proxySessionSignKey
		}
		if api.proxySessionNonceLength > 0 {
			client.NonceEnabled = true
			client.NonceLength = api.proxySessionNonceLength
		}
		client.SetOverrideParam("api_format", "json")
		resp, err := client.Get(api.proxySessionAction, nil, nil)
		if err != nil {
			// 不显示该日志，因为要重试的可能性比较大
			// logger.Error("Fetch session encrypt key failed: %s", err.Error())
			time.Sleep(time.Second * time.Duration(1))
			continue
		}

		j, err := resp.Json()
		if err != nil {
			logger.Error("Unrecognized result when fetch session encrypt key!")
			time.Sleep(time.Second * time.Duration(1))
			continue
		}

		rsCode := j.Get("CODE").MustString()
		if rsCode != "ok" {
			logger.Error("API return code '%s' when fetch session encrypt key!", rsCode)
			time.Sleep(time.Second * time.Duration(1))
			continue
		}

		data := j.Get("DATA").MustArray()
		keyPairs := make([][]byte, 0, len(data))
		hasErr := false
		for _, v := range data {
			s, ok := v.(string)
			if !ok {
				logger.Error("API return code '%s' when fetch session encrypt key!", rsCode)
				hasErr = true
				break
			}
			key, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				logger.Error("Unrecognized result of session encrypt key!")
				hasErr = true
				break
			}
			keyPairs = append(keyPairs, key)
		}
		if hasErr {
			time.Sleep(time.Second * time.Duration(1))
			continue
		}

		// 更新当前 key
		web.sessionStoreMutex.Lock()
		for _, local := range api.proxySessionMap {
			api.proxySessionKeyPairs = keyPairs
			web.GetSessionStore(local).LoadKeyPairs(keyPairs)
		}
		web.sessionStoreMutex.Unlock()

		if web.debug {
			logger.Debug("Successfully update cookie encrypt key from: %s", api.server)
		}

		// 更新成功，退出
		break
	}
}
