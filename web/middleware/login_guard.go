package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/entity"
	"github.com/mhsanaei/3x-ui/v2/web/locale"
	"github.com/mhsanaei/3x-ui/v2/web/network"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

// A permanent ban applies to the entire panel, including existing sessions.
func LoginIPGuard(resolver *network.ClientIPResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip, err := resolver.Resolve(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, entity.Msg{Msg: locale.I18n(locale.Web, "pages.login.toasts.ipUnavailable")})
			return
		}
		c.Set("client_ip", ip.String())
		banned, err := service.IsLoginIPBanned(ip.String())
		if err != nil {
			logger.Warning("login protection lookup failed:", err)
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, entity.Msg{Msg: locale.I18n(locale.Web, "pages.login.toasts.protectionUnavailable")})
			return
		}
		if banned {
			c.AbortWithStatusJSON(http.StatusForbidden, entity.Msg{Msg: locale.I18n(locale.Web, "pages.login.toasts.ipBanned")})
			return
		}
		c.Next()
	}
}
