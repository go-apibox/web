package web

import (
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-apibox/cache"
	"github.com/go-apibox/session"
	"github.com/go-apibox/utils"
	"github.com/bamiaux/rez"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"gopkg.in/flosch/pongo2.v3"
)

var templateSet *pongo2.TemplateSet

func init() {
	templateSet = pongo2.NewSet("web")

	// 增加key filter
	pongo2.RegisterFilter("key", func(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
		if in.Contains(param) {
			v := in.Interface()
			if vv, ok := v.(map[interface{}]interface{}); ok {
				key := param.String()
				if val, has := vv[key]; has {
					return pongo2.AsValue(val), nil
				} else {
					return pongo2.AsValue(""), nil
				}
			} else {
				return pongo2.AsValue(""), nil
			}
		}
		return pongo2.AsValue(""), nil
	})

	// 增加dump filter
	pongo2.RegisterFilter("dump", func(in *pongo2.Value, param *pongo2.Value) (*pongo2.Value, *pongo2.Error) {
		return pongo2.AsValue(fmt.Sprint(in.Interface())), nil
	})

	// 设置默认mime
	mime.AddExtensionType(".exe", "application/octet-stream")
	mime.AddExtensionType(".crt", "application/octet-stream")
	mime.AddExtensionType(".cer", "application/octet-stream")
	mime.AddExtensionType(".key", "application/octet-stream")
}

type Web struct {
	webRoot       string
	host          string
	sessionDomain string

	pages   []*Page
	apis    []*API
	statics []*Static

	sessionStoreMap   map[string]*session.CookieStore // 支持不同的session使用不同的cookiestore
	sessionStoreMutex sync.RWMutex

	injectData        map[string]interface{}
	injectIncludeData map[string]string
	injectSessionMap  map[string]string

	captchaCache *cache.Cache

	ServerName string

	debug bool

	RestartFunc func()
}

type Page struct {
	path     string
	template string
	data     map[string]interface{}
	headers  map[string]string // http头

	public                 bool
	disallowSpiders        bool
	unauthedRedirect       bool
	unauthedRedirectMethod string
	authSessionName        string // 用于验证登录的session
	authSessionKey         string
	loginUrl               string

	excepts map[string][]string
}

type Static struct {
	path               string
	root               string
	maxAge             int
	imageResizeEnabled bool
	imageResizeSizes   []string
	maskAlias          string
}

type API struct {
	path        string
	server      string
	addr        string
	signKey     string
	nonceLength int
	params      map[string]string

	proxySessionKeyPairs    [][]byte
	proxySessionEnabled     bool
	proxySessionMap         map[string]string
	proxySessionRMap        map[string]string
	proxySessionAction      string
	proxySessionSignKey     string
	proxySessionNonceLength int

	captchaMatcher *utils.Matcher
	captchaConfigs map[string]*CaptchaConfig
}

type CaptchaConfig struct {
	identifier   string
	maxFailCount int
}

func New(webRoot, host string) (*Web, error) {
	w := new(Web)
	w.webRoot = webRoot
	w.host = host
	w.pages = make([]*Page, 0)
	w.apis = make([]*API, 0)
	w.statics = make([]*Static, 0)
	w.captchaCache = cache.NewCacheEx(time.Duration(3600)*time.Second, time.Duration(60)*time.Second)
	w.ServerName = "apibox/webserver"

	var err error
	defaultStore, err := session.NewCookieStore(false, "")
	if err != nil {
		return w, err
	}
	w.sessionStoreMap = map[string]*session.CookieStore{
		"default": defaultStore,
	}

	w.injectData = make(map[string]interface{})
	w.injectIncludeData = make(map[string]string)
	w.injectSessionMap = make(map[string]string)
	w.debug = false

	return w, err
}

func FromConfig(webRoot, host string, config *WebConfig) (*Web, error) {
	w, err := New(webRoot, host)
	if err != nil {
		return w, err
	}

	w.Debug(config.GetDebug())
	w.AddPages(config.GetPages())
	w.AddAPIs(config.GetAPIs())
	w.AddStatics(config.GetStatics())
	w.PageInjectMap(config.GetPageInjectData())
	w.PageInjectIncludeDataMap(config.GetPageInjectIncludeData())
	w.PageInjectSessionMap(config.GetPageInjectSessions())

	return w, nil
}

func (web *Web) Reload(webRoot, host string, config *WebConfig) {
	// 重新初始化
	web.webRoot = webRoot
	web.host = host
	web.pages = make([]*Page, 0)
	web.apis = make([]*API, 0)
	web.statics = make([]*Static, 0)
	web.injectData = make(map[string]interface{})
	web.injectIncludeData = make(map[string]string)
	web.injectSessionMap = make(map[string]string)
	web.debug = false

	web.Debug(config.GetDebug())
	web.AddPages(config.GetPages())
	web.AddAPIs(config.GetAPIs())
	web.AddStatics(config.GetStatics())
	web.PageInjectMap(config.GetPageInjectData())
	web.PageInjectIncludeDataMap(config.GetPageInjectIncludeData())
	web.PageInjectSessionMap(config.GetPageInjectSessions())
}

func (web *Web) SetSessionDomain(sessionDomain string) {
	web.sessionDomain = sessionDomain
}

func (web *Web) GetSessionStore(sessionName string) *session.CookieStore {
	cs, ok := web.sessionStoreMap[sessionName]
	if !ok {
		return web.sessionStoreMap["default"]
	}
	return cs
}

// AddPage add a new page to web.
func (web *Web) AddPage(page *Page) *Web {
	web.pages = append(web.pages, page)
	return web
}

// AddPages add new pages to web.
func (web *Web) AddPages(pages []*Page) *Web {
	web.pages = append(web.pages, pages...)
	return web
}

// AddAPI add a new api backend to web.
func (web *Web) AddAPI(api *API) *Web {
	web.apis = append(web.apis, api)
	return web
}

// AddAPIs add new api backends to web.
func (web *Web) AddAPIs(apis []*API) *Web {
	web.apis = append(web.apis, apis...)
	return web
}

// AddStatic add a new static path to web.
func (web *Web) AddStatic(static *Static) *Web {
	web.statics = append(web.statics, static)
	return web
}

// AddStatics add new static paths to web.
func (web *Web) AddStatics(statics []*Static) *Web {
	for _, s := range statics {
		web.statics = append(web.statics, s)
	}
	return web
}

// PageInject will inject data to all page.
func (web *Web) PageInject(name string, value interface{}) *Web {
	web.injectData[name] = value
	return web
}

// PageInjectMap will inject data map to all page.
func (web *Web) PageInjectMap(dataMap map[string]interface{}) *Web {
	for k, v := range dataMap {
		web.injectData[k] = v
	}
	return web
}

// PageInjectIncludeData will inject include data to all page.
func (web *Web) PageInjectIncludeData(name, includeData string) *Web {
	web.injectIncludeData[name] = includeData
	return web
}

// PageInjectIncludeDataMap will inject include data map to all page.
func (web *Web) PageInjectIncludeDataMap(dataMap map[string]string) *Web {
	for k, v := range dataMap {
		web.injectIncludeData[k] = v
	}
	return web
}

// PageInjectSession will inject session data to all page.
func (web *Web) PageInjectSession(name, sessionName string) *Web {
	web.injectSessionMap[name] = sessionName
	return web
}

// PageInjectSessionMap will inject session map to all page.
func (web *Web) PageInjectSessionMap(sessionMap map[string]string) *Web {
	for k, v := range sessionMap {
		web.injectSessionMap[k] = v
	}
	return web
}

// Debug set if print out debug message.
func (web *Web) Debug(debug bool) *Web {
	web.debug = debug
	return web
}

func (web *Web) Handler() http.Handler {
	router := mux.NewRouter()
	if web.host != "" {
		subRouter := router.Host(web.host).Subrouter()
		web.RouteHandler(subRouter)
	} else {
		web.RouteHandler(router)
	}
	// go1.7版本的mux不会自动调用gorilla/context的ClearHander，需要手动清理
	return serverNameHandler(web.ServerName, context.ClearHandler(router))
}

func serverNameHandler(serverName string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Server", serverName)
		h.ServeHTTP(w, r)
	})
}

func corsHandler(allowAllExts []string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, ext := range allowAllExts {
			if strings.HasSuffix(r.RequestURI, ext) {
				w.Header().Add("Access-Control-Allow-Origin", "*")
				break
			}
		}
		h.ServeHTTP(w, r)
	})
}

func maxAgeHandler(seconds int, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", fmt.Sprintf("max-age=%d, public, must-revalidate, proxy-revalidate", seconds))
		h.ServeHTTP(w, r)
	})
}

func imageResizeHandler(rootPath string, imageResizeSizes []string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer h.ServeHTTP(w, r)

		// 检测文件名是否符合格式：{FILE}_{N}x{N}.{EXT}
		fileName := filepath.Base(r.RequestURI)
		fileExt := filepath.Ext(fileName)

		// 除去扩展名
		if fileExt != "" {
			fileName = fileName[:len(fileName)-len(fileExt)]
		}

		// 查找是否带_
		if pos := strings.LastIndexByte(fileName, '_'); pos > 0 {
			reqSize := fileName[pos+1:]
			rawFileName := fileName[:pos]
			for _, size := range imageResizeSizes {
				if size == reqSize {
					sizeFields := strings.Split(reqSize, "x")
					if len(sizeFields) != 2 {
						continue
					}
					width, err := strconv.Atoi(sizeFields[0])
					if err != nil {
						return
					}
					height, err := strconv.Atoi(sizeFields[1])
					if err != nil {
						return
					}

					// 判断原图是否存在，不存在则不处理
					rawImgPath := filepath.Join(rootPath, filepath.Dir(r.RequestURI), rawFileName+fileExt)
					rawFi, err := os.Stat(rawImgPath)
					if err != nil {
						return
					}

					// 判断图片是否存在且最新
					imgPath := filepath.Join(rootPath, r.RequestURI)
					fi, err := os.Stat(imgPath)
					if err != nil {
						if !os.IsNotExist(err) {
							return
						}
					} else {
						if fi.ModTime().Equal(rawFi.ModTime()) {
							// 存在且时间一样，无须处理
							return
						}
					}

					// 自动生成图片
					// 装载原图
					f, err := os.Open(rawImgPath)
					if err != nil {
						return
					}
					defer f.Close()
					rawImg, _, err := image.Decode(f)
					if err != nil {
						return
					}

					var img image.Image
					rect := image.Rect(0, 0, width, height)
					switch inst := rawImg.(type) {
					case *image.Alpha:
						img = image.NewAlpha(rect)
					case *image.Alpha16:
						img = image.NewAlpha16(rect)
					case *image.CMYK:
						img = image.NewCMYK(rect)
					case *image.Gray:
						img = image.NewGray(rect)
					case *image.Gray16:
						img = image.NewGray16(rect)
					case *image.NRGBA:
						img = image.NewNRGBA(rect)
					case *image.NRGBA64:
						img = image.NewNRGBA64(rect)
					case *image.Paletted:
						img = image.NewPaletted(rect, inst.Palette)
					case *image.RGBA:
						img = image.NewRGBA(rect)
					case *image.RGBA64:
						img = image.NewRGBA64(rect)
					case *image.YCbCr:
						img = image.NewYCbCr(rect, inst.SubsampleRatio)
					default:
						return
					}
					if err := rez.Convert(img, rawImg, rez.NewLanczosFilter(12)); err != nil {
						return
					}

					out, err := os.Create(imgPath)
					if err != nil {
						return
					}
					defer out.Close()

					if fileExt == ".jpg" {
						if err := jpeg.Encode(out, img, nil); err != nil {
							return
						}
					} else {
						if err := png.Encode(out, img); err != nil {
							return
						}
					}

					// 修改时间
					if err = os.Chtimes(imgPath, rawFi.ModTime(), rawFi.ModTime()); err != nil {
						return
					}

					return
				}
			}
		} else {
			return
		}
	})
}

// 参照 http.StripPrefix，但支持 gorilla 路径规则
func stripPrefixPatternHandler(prefixPattern string, h http.Handler) http.Handler {
	if prefixPattern == "" {
		return h
	}
	re, err := regexp.Compile(prefixPattern)
	if err != nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := re.ReplaceAllString(r.URL.Path, "")
		if len(p) < len(r.URL.Path) {
			r.URL.Path = p
			h.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	})
}

func (web *Web) RouteHandler(router *mux.Router) http.Handler {
	if web.debug {
		logger.Debug(strings.Repeat("-", 50))
		if len(web.apis) == 0 {
			logger.Debug("NO API DEFINED")
		}
	}

	// 处理API配置
	for _, api := range web.apis {
		if web.debug {
			logger.Debug("API: %s %s %s", api.path, api.server, api.addr)
		}
		router.HandleFunc(api.path, web.NewAPIFunc(api))
	}

	if web.debug {
		logger.Debug(strings.Repeat("-", 50))
		if len(web.statics) == 0 {
			logger.Debug("NO STATIC DEFINED")
		}
	}

	// 处理静态文件配置
	for _, static := range web.statics {
		rootPath := filepath.Join(web.webRoot, static.root)
		if web.debug {
			logger.Debug("STATIC: %s %s", static.path, rootPath)
		}
		var handler http.Handler
		if static.maskAlias != "" {
			maskAliasPath := filepath.Join(web.webRoot, static.maskAlias)
			if _, err := os.Stat(maskAliasPath); err == nil {
				var urlPrefix string
				if strings.HasSuffix(static.path, "/") {
					// 路径为目录
					urlPrefix = static.path
				} else {
					// 路径为文件
					urlPrefix = filepath.Dir(static.path)
				}
				pattern, _ := mux.NewRouter().PathPrefix(urlPrefix).GetPathRegexp()
				handler = stripPrefixPatternHandler(pattern, http.FileServer(http.Dir(maskAliasPath)))
			} else {
				handler = http.FileServer(http.Dir(rootPath))
			}
		} else {
			handler = http.FileServer(http.Dir(rootPath))
		}
		handler = maxAgeHandler(static.maxAge, handler)
		handler = corsHandler([]string{".eot", ".svg", ".ttf", ".woff", ".woff2"}, handler)
		if static.imageResizeEnabled && len(static.imageResizeSizes) > 0 {
			handler = imageResizeHandler(rootPath, static.imageResizeSizes, handler)
		}
		if strings.HasSuffix(static.path, "/") {
			// 路径为目录
			router.PathPrefix(static.path).Handler(handler)
		} else {
			// 路径为文件
			router.Handle(static.path, handler)
		}
	}

	if web.debug {
		logger.Debug(strings.Repeat("-", 50))
		if len(web.pages) == 0 {
			logger.Debug("NO PAGE DEFINED")
		}
	}

	// 处理模板页面配置
	for _, page := range web.pages {
		if web.debug {
			logger.Debug("PAGE: %s %s", page.path, page.template)
		}
		switch page.template {
		case "@login":
			router.HandleFunc(page.path, web.NewLoginFunc(page))
		case "@logout":
			router.HandleFunc(page.path, web.NewLogoutFunc(page))
		case "@captcha":
			router.HandleFunc(page.path, web.NewCaptchaFunc(page))
		case "@restart":
			router.HandleFunc(page.path, web.NewRestartFunc(page))
		default:
			router.HandleFunc(page.path, web.NewPageFunc(page))
		}
	}

	if web.debug {
		logger.Debug(strings.Repeat("-", 50))
	}

	return router
}
