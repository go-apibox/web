package web

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-apibox/config"
	"github.com/go-apibox/utils"
)

type WebConfig config.Config

func NewConfig(cfg *config.Config) *WebConfig {
	return (*WebConfig)(cfg)
}

func (wc *WebConfig) GetDebug() bool {
	cfg := (*config.Config)(wc)
	return cfg.GetDefaultBool("web.debug", false)
}

func (wc *WebConfig) GetBaseUrl() string {
	cfg := (*config.Config)(wc)
	return cfg.GetDefaultString("web.base_url", "/")
}

func (wc *WebConfig) GetPageInjectData() map[string]interface{} {
	cfg := (*config.Config)(wc)
	return cfg.GetDefaultMap("web.page_setting.inject.data", make(map[string]interface{}))
}

func (wc *WebConfig) GetPageInjectIncludeData() map[string]string {
	cfg := (*config.Config)(wc)

	rt := make(map[string]string)
	data := cfg.GetDefaultMap("web.page_setting.inject.include_data", make(map[string]interface{}))
	for k, v := range data {
		if vv, ok := v.(string); ok {
			rt[k] = vv
		}
	}

	return rt
}

func (wc *WebConfig) GetPageInjectSessions() map[string]string {
	cfg := (*config.Config)(wc)

	rt := make(map[string]string)
	sessions := cfg.GetDefaultMap("web.page_setting.inject.session", map[string]interface{}{
		"session": "default",
	})
	for k, v := range sessions {
		if vv, ok := v.(string); ok {
			rt[k] = vv
		}
	}

	return rt
}

func (wc *WebConfig) GetPages() []*Page {
	cfg := (*config.Config)(wc)

	d, oldd := string([]byte{0x0}), cfg.Delimiter
	cfg.Delimiter = d
	defer func() { cfg.Delimiter = oldd }()

	pageCount, err := cfg.Len("web" + d + "pages")
	if err != nil || pageCount == 0 {
		return make([]*Page, 0)
	}

	basePath := cfg.GetDefaultString("web"+d+"page_setting"+d+"base_dir", "")

	// 全局默认配置处理
	globalPrefix := "web" + d + "page_setting" + d + "global" + d
	tGlobalHeaders := cfg.GetDefaultMap(globalPrefix+"headers", map[string]interface{}{})
	globalPerm := cfg.GetDefaultString(globalPrefix+"perm", "public")
	globalDisallowSpiders := cfg.GetDefaultBool(globalPrefix+"disallow_spiders", false)
	globalUnauthedRedirect := cfg.GetDefaultBool(globalPrefix+"unauthed_redirect", true)
	globalUnauthedRedirectMethod := cfg.GetDefaultString(globalPrefix+"unauthed_redirect_method", "http")
	globalLoginUrl := cfg.GetDefaultString(globalPrefix+"login_url", "/login?from={$FROM_URL$}")
	globalSessionAuthKey := cfg.GetDefaultString(globalPrefix+"session_auth_key", "default.authed")

	globalHeaders := make(map[string]string, len(tGlobalHeaders))
	for k, v := range tGlobalHeaders {
		globalHeaders[k], _ = v.(string)
	}

	pages := make([]*Page, 0, pageCount)
	pagesPrefix := "web" + d + "pages"
	for i := 0; i < pageCount; i++ {
		pagePrefix := pagesPrefix + fmt.Sprintf("[%d]", i) + d
		pagePaths, err := cfg.GetSubKeys(pagesPrefix + fmt.Sprintf("[%d]", i))
		if err != nil || len(pagePaths) == 0 {
			continue
		}
		pagePath := pagePaths[0]

		pagePrefix = pagePrefix + pagePath + d

		// 模板路径
		tmpl := cfg.GetDefaultString(pagePrefix+"tmpl", "")
		if tmpl == "" {
			continue
		}
		if tmpl[0] != '@' {
			tmpl = filepath.Join(basePath, tmpl)
		}

		// 模板数据
		data := cfg.GetDefaultMap(pagePrefix+"data", map[string]interface{}{})

		// http头
		tHeaders := cfg.GetDefaultMap(pagePrefix+"headers", map[string]interface{}{})
		headers := make(map[string]string, len(tHeaders))
		for k, v := range tGlobalHeaders {
			headers[k], _ = v.(string)
		}
		for k, v := range tHeaders {
			headers[k], _ = v.(string)
		}

		// 权限
		perm := cfg.GetDefaultString(pagePrefix+"perm", globalPerm)
		excepts := make(map[string][]string)
		keys, err := cfg.GetSubKeys(pagePrefix + "excepts")
		if err == nil {
			for _, key := range keys {
				matches := cfg.GetDefaultStringArray(pagePrefix+"excepts"+d+key, []string{})
				if len(matches) > 0 {
					excepts[key] = matches
				}
			}
		}
		disallowSpiders := cfg.GetDefaultBool(pagePrefix+"disallow_spiders", globalDisallowSpiders)
		unauthedRedirect := cfg.GetDefaultBool(pagePrefix+"unauthed_redirect", globalUnauthedRedirect)
		unauthedRedirectMethod := cfg.GetDefaultString(pagePrefix+"unauthed_redirect_method", globalUnauthedRedirectMethod)
		sessionAuthKey := cfg.GetDefaultString(pagePrefix+"session_auth_key", globalSessionAuthKey)
		parts := strings.SplitN(sessionAuthKey, ".", 2)
		if len(parts) != 2 {
			parts = []string{"default", parts[0]}
		}
		authSessionName := parts[0]
		authSessionKey := parts[1]
		loginUrl := cfg.GetDefaultString(pagePrefix+"login_url", globalLoginUrl)

		pages = append(pages, &Page{
			path:                   pagePath,
			template:               tmpl,
			data:                   data,
			headers:                headers,
			public:                 perm == "public",
			disallowSpiders:        disallowSpiders,
			unauthedRedirect:       unauthedRedirect,
			unauthedRedirectMethod: unauthedRedirectMethod,
			authSessionName:        authSessionName,
			authSessionKey:         authSessionKey,
			loginUrl:               loginUrl,
			excepts:                excepts,
		})
	}

	return pages
}

func (wc *WebConfig) GetAPIs() []*API {
	cfg := (*config.Config)(wc)

	d, oldd := string([]byte{0x0}), cfg.Delimiter
	cfg.Delimiter = d
	defer func() { cfg.Delimiter = oldd }()

	apiCount, err := cfg.Len("web" + d + "apis")
	if err != nil || apiCount == 0 {
		return make([]*API, 0)
	}

	apis := make([]*API, 0, apiCount)
	apisPrefix := "web" + d + "apis"
	for i := 0; i < apiCount; i++ {
		apiPrefix := apisPrefix + fmt.Sprintf("[%d]", i) + d
		apiPaths, err := cfg.GetSubKeys(apisPrefix + fmt.Sprintf("[%d]", i))
		if err != nil || len(apiPaths) == 0 {
			continue
		}
		apiPath := apiPaths[0]

		apiPrefix = apiPrefix + apiPath + d
		server := cfg.GetDefaultString(apiPrefix+"server", "")
		if server == "" {
			continue
		}
		addr := cfg.GetDefaultString(apiPrefix+"addr", "")
		if addr != "" {
			addr = utils.AbsPath(addr)
		}
		signKey := cfg.GetDefaultString(apiPrefix+"sign_key", "")
		nonceLength := cfg.GetDefaultInt(apiPrefix+"nonce_length", 16)
		tParams := cfg.GetDefaultMap(apiPrefix+"params", make(map[string]interface{}))

		proxySessionPrefix := apiPrefix + "proxy_session" + d
		proxySessionEnabled := cfg.GetDefaultBool(proxySessionPrefix+"enabled", true)
		tMap := cfg.GetDefaultMap(proxySessionPrefix+"session_map", map[string]interface{}{"default": "default"})
		proxySessionMap := make(map[string]string)
		proxySessionRMap := make(map[string]string)
		for k, v := range tMap {
			if vv, ok := v.(string); ok {
				proxySessionMap[k] = vv
				proxySessionRMap[vv] = k
			}
		}
		proxySessionAction := cfg.GetDefaultString(proxySessionPrefix+"encrypt_key_action", "APIBox.Session.GetKey")
		proxySessionSignKey := cfg.GetDefaultString(proxySessionPrefix+"sign_key", signKey)
		proxySessionNonceLength := cfg.GetDefaultInt(proxySessionPrefix+"nonce_length", nonceLength)

		captchaActionPrefix := apiPrefix + "captcha_actions" + d
		captchaActionMap := cfg.GetDefaultMap(apiPrefix+"captcha_actions", map[string]interface{}{})
		captchaActions := make([]string, 0, len(captchaActionMap))
		captchaConfigs := make(map[string]*CaptchaConfig)
		for action, _ := range captchaActionMap {
			captchaActions = append(captchaActions, action)
			captchaConfig := new(CaptchaConfig)
			pre := captchaActionPrefix + action + d
			captchaConfig.identifier = cfg.GetDefaultString(pre+"identifier", "")
			captchaConfig.maxFailCount = cfg.GetDefaultInt(pre+"max_fail_count", 0)
			captchaConfigs[action] = captchaConfig
		}

		params := make(map[string]string)
		for k, v := range tParams {
			params[k] = fmt.Sprint(v)
		}

		ccMatcher := utils.NewMatcher().SetWhiteList(captchaActions)

		apis = append(apis, &API{
			path:        apiPath,
			server:      server,
			addr:        addr,
			signKey:     signKey,
			nonceLength: nonceLength,
			params:      params,

			proxySessionKeyPairs:    make([][]byte, 0),
			proxySessionEnabled:     proxySessionEnabled,
			proxySessionMap:         proxySessionMap,
			proxySessionRMap:        proxySessionRMap,
			proxySessionAction:      proxySessionAction,
			proxySessionSignKey:     proxySessionSignKey,
			proxySessionNonceLength: proxySessionNonceLength,

			captchaMatcher: ccMatcher,
			captchaConfigs: captchaConfigs,
		})
	}

	return apis
}

func (wc *WebConfig) GetStatics() []*Static {
	cfg := (*config.Config)(wc)

	d, oldd := string([]byte{0x0}), cfg.Delimiter
	cfg.Delimiter = d
	defer func() { cfg.Delimiter = oldd }()

	staticCount, err := cfg.Len("web" + d + "statics")
	if err != nil || staticCount == 0 {
		return make([]*Static, 0)
	}

	defaultMaxAge := cfg.GetDefaultInt("web"+d+"static_setting"+d+"max_age", 3600*24*365)

	statics := make([]*Static, 0, staticCount)
	staticsPrefix := "web" + d + "statics"
	for i := 0; i < staticCount; i++ {
		staticPrefix := staticsPrefix + fmt.Sprintf("[%d]", i) + d
		staticPaths, err := cfg.GetSubKeys(staticsPrefix + fmt.Sprintf("[%d]", i))
		if err != nil || len(staticPaths) == 0 {
			continue
		}
		staticPath := staticPaths[0]

		staticPrefix = staticPrefix + staticPath + d
		// 根路径
		root := cfg.GetDefaultString(staticPrefix+"root", "")
		if root == "" {
			continue
		}
		// 缓存
		maxAge := cfg.GetDefaultInt(staticPrefix+"max_age", defaultMaxAge)
		// 图片调整大小
		imageResizeEnabled := cfg.GetDefaultBool(staticPrefix+"image_resize_enabled", false)
		imageResizeSizes := cfg.GetDefaultStringArray(staticPrefix+"image_resize_sizes", []string{})
		// 遮罩路径，如果遮罩路径存在，则使用遮罩路径
		maskAlias := cfg.GetDefaultString(staticPrefix+"mask_alias", "")

		statics = append(statics, &Static{
			path:               staticPath,
			root:               root,
			maxAge:             maxAge,
			imageResizeEnabled: imageResizeEnabled,
			imageResizeSizes:   imageResizeSizes,
			maskAlias:          maskAlias,
		})
	}

	return statics
}
