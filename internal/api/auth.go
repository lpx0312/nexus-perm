package api

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"nexus-perm/internal/auth"
)

// 登录防爆破：同一用户名连续失败 N 次后锁定一段时间（内存计数，重启清零）。
const (
	loginMaxFailures = 5
	loginLockDuration = 15 * time.Minute
)

type loginFailure struct {
	count       int
	lockedUntil time.Time
}

type loginGuard struct {
	mu       sync.Mutex
	failures map[string]*loginFailure
}

func newLoginGuard() *loginGuard { return &loginGuard{failures: map[string]*loginFailure{}} }

func (g *loginGuard) check(username string) (bool, time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f, ok := g.failures[username]
	if !ok {
		return false, 0
	}
	if f.lockedUntil.After(time.Now()) {
		return true, time.Until(f.lockedUntil)
	}
	return false, 0
}

func (g *loginGuard) recordFailure(username string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f, ok := g.failures[username]
	if !ok {
		f = &loginFailure{}
		g.failures[username] = f
	}
	f.count++
	if f.count >= loginMaxFailures {
		f.lockedUntil = time.Now().Add(loginLockDuration)
		f.count = 0
	}
}

func (g *loginGuard) recordSuccess(username string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.failures, username)
}

// ---------------- 中间件 ----------------

// authRequired 除 /api/auth/login 外的所有 API 均需登录。
func (s *Server) authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未登录或登录已过期，请重新登录"})
			c.Abort()
			return
		}
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "认证格式错误"})
			c.Abort()
			return
		}
		claims, err := s.authSvc.ValidateToken(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "登录已过期，请重新登录"})
			c.Abort()
			return
		}
		// 用户被禁用/删除后，已签发的 token 立即失效
		u, err := s.st.GetPlatformUserByID(claims.UserID)
		if err != nil || !u.Enabled {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "账号不存在或已被禁用"})
			c.Abort()
			return
		}
		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Next()
	}
}

// ---------------- 登录/登出 ----------------

type loginReq struct {
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
	RememberMe bool   `json:"remember_me"`
}

// failStatus 带状态码的错误响应。
func failStatus(c *gin.Context, status int, err error) {
	c.JSON(status, gin.H{"error": err.Error()})
}

func (s *Server) login(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, &simpleErr{"用户名和密码不能为空"})
		return
	}
	ip := c.ClientIP()

	if locked, remaining := s.guard.check(req.Username); locked {
		_ = s.st.AddLoginLog(req.Username, ip, "failed", "失败次数过多已锁定")
		failStatus(c, http.StatusTooManyRequests,
			&simpleErr{"登录失败次数过多，请 " + strconv.Itoa(int(remaining.Minutes())+1) + " 分钟后再试"})
		return
	}

	u, err := s.st.GetPlatformUserByUsername(req.Username)
	if err != nil {
		s.guard.recordFailure(req.Username)
		_ = s.st.AddLoginLog(req.Username, ip, "failed", "用户不存在")
		failStatus(c, http.StatusUnauthorized, &simpleErr{"用户名或密码错误"})
		return
	}
	if !u.Enabled {
		_ = s.st.AddLoginLog(req.Username, ip, "failed", "账号已被禁用")
		c.JSON(http.StatusForbidden, gin.H{"error": "账号已被禁用，请联系管理员"})
		return
	}
	if !s.authSvc.CheckPassword(u.PasswordHash, req.Password) {
		s.guard.recordFailure(req.Username)
		_ = s.st.AddLoginLog(req.Username, ip, "failed", "密码错误")
		failStatus(c, http.StatusUnauthorized, &simpleErr{"用户名或密码错误"})
		return
	}
	s.guard.recordSuccess(req.Username)

	token, expiresAt, err := s.authSvc.GenerateToken(u.ID, u.Username, req.RememberMe)
	if err != nil {
		fail(c, err)
		return
	}
	_ = s.st.TouchPlatformUserLogin(u.ID)
	_ = s.st.AddLoginLog(u.Username, ip, "success", "登录成功")

	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339),
		"user": gin.H{
			"id":       u.ID,
			"username": u.Username,
			"email":    u.Email,
		},
	})
}

func (s *Server) logout(c *gin.Context) {
	username, _ := c.Get("username")
	_ = s.st.AddLoginLog(username.(string), c.ClientIP(), "success", "主动登出")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) me(c *gin.Context) {
	userID, _ := c.Get("userID")
	u, err := s.st.GetPlatformUserByID(userID.(int64))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":       u.ID,
		"username": u.Username,
		"email":    u.Email,
	})
}

type changePasswordReq struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// changePassword 本人修改密码（需验证原密码）。
func (s *Server) changePassword(c *gin.Context) {
	var req changePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, &simpleErr{"请输入原密码和新密码"})
		return
	}
	if err := auth.ValidateStrongPassword(req.NewPassword); err != nil {
		fail(c, err)
		return
	}
	userID, _ := c.Get("userID")
	u, err := s.st.GetPlatformUserByID(userID.(int64))
	if err != nil {
		fail(c, &simpleErr{"用户不存在"})
		return
	}
	if !s.authSvc.CheckPassword(u.PasswordHash, req.OldPassword) {
		fail(c, &simpleErr{"原密码错误"})
		return
	}
	hash, err := s.authSvc.HashPassword(req.NewPassword)
	if err != nil {
		fail(c, err)
		return
	}
	if err := s.st.SetPlatformUserPassword(u.ID, hash); err != nil {
		fail(c, err)
		return
	}
	_ = s.st.AddAudit("platform-user", u.Username, "修改了自己的密码", "OK")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ---------------- 平台用户管理 ----------------

func (s *Server) listPlatformUsers(c *gin.Context) {
	users, err := s.st.ListPlatformUsers()
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

type createPlatformUserReq struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email"`
}

func (s *Server) createPlatformUser(c *gin.Context) {
	var req createPlatformUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, err)
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		fail(c, &simpleErr{"用户名不能为空"})
		return
	}
	if err := auth.ValidateStrongPassword(req.Password); err != nil {
		fail(c, err)
		return
	}
	hash, err := s.authSvc.HashPassword(req.Password)
	if err != nil {
		fail(c, err)
		return
	}
	id, err := s.st.CreatePlatformUser(req.Username, hash, req.Email)
	if err != nil {
		fail(c, &simpleErr{"创建失败：用户名可能已存在"})
		return
	}
	actor, _ := c.Get("username")
	_ = s.st.AddAudit("platform-user", req.Username, "由 "+actor.(string)+" 创建", "OK")
	c.JSON(http.StatusOK, gin.H{"id": id})
}

type updatePlatformUserReq struct {
	Email   *string `json:"email"`
	Enabled *bool   `json:"enabled"`
}

func (s *Server) updatePlatformUser(c *gin.Context) {
	id, err := idParam(c)
	if err != nil {
		fail(c, err)
		return
	}
	var req updatePlatformUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, err)
		return
	}
	userID, _ := c.Get("userID")
	if req.Enabled != nil && !*req.Enabled && userID.(int64) == id {
		fail(c, &simpleErr{"不能禁用自己的账号"})
		return
	}
	u, err := s.st.GetPlatformUserByID(id)
	if err != nil {
		fail(c, &simpleErr{"用户不存在"})
		return
	}
	if err := s.st.UpdatePlatformUser(id, req.Email, req.Enabled); err != nil {
		fail(c, err)
		return
	}
	actor, _ := c.Get("username")
	detail := "由 " + actor.(string) + " 更新"
	if req.Enabled != nil {
		detail += fmtEnabled(*req.Enabled)
	}
	_ = s.st.AddAudit("platform-user", u.Username, detail, "OK")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func fmtEnabled(enabled bool) string {
	if enabled {
		return "（启用）"
	}
	return "（禁用）"
}

func (s *Server) deletePlatformUser(c *gin.Context) {
	id, err := idParam(c)
	if err != nil {
		fail(c, err)
		return
	}
	userID, _ := c.Get("userID")
	if userID.(int64) == id {
		fail(c, &simpleErr{"不能删除自己的账号"})
		return
	}
	u, err := s.st.GetPlatformUserByID(id)
	if err != nil {
		fail(c, &simpleErr{"用户不存在"})
		return
	}
	// 保留至少一个可用账号，防止把所有人都删掉后锁死自己
	users, err := s.st.ListPlatformUsers()
	if err != nil {
		fail(c, err)
		return
	}
	enabledCount := 0
	for _, x := range users {
		if x.Enabled {
			enabledCount++
		}
	}
	if u.Enabled && enabledCount <= 1 {
		fail(c, &simpleErr{"这是最后一个可用账号，不能删除"})
		return
	}
	if err := s.st.DeletePlatformUser(id); err != nil {
		fail(c, err)
		return
	}
	actor, _ := c.Get("username")
	_ = s.st.AddAudit("platform-user", u.Username, "由 "+actor.(string)+" 删除", "OK")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type resetPasswordReq struct {
	NewPassword string `json:"new_password" binding:"required"`
}

// resetPlatformUserPassword 管理员重置他人密码。
func (s *Server) resetPlatformUserPassword(c *gin.Context) {
	id, err := idParam(c)
	if err != nil {
		fail(c, err)
		return
	}
	var req resetPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, err)
		return
	}
	if err := auth.ValidateStrongPassword(req.NewPassword); err != nil {
		fail(c, err)
		return
	}
	u, err := s.st.GetPlatformUserByID(id)
	if err != nil {
		fail(c, &simpleErr{"用户不存在"})
		return
	}
	hash, err := s.authSvc.HashPassword(req.NewPassword)
	if err != nil {
		fail(c, err)
		return
	}
	if err := s.st.SetPlatformUserPassword(id, hash); err != nil {
		fail(c, err)
		return
	}
	actor, _ := c.Get("username")
	_ = s.st.AddAudit("platform-user", u.Username, "密码被 "+actor.(string)+" 重置", "OK")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) listLoginLogs(c *gin.Context) {
	logs, err := s.st.ListLoginLogs(200)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs})
}
