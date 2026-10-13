package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"nexus-perm/internal/auth"
	"nexus-perm/internal/nexus"
	"nexus-perm/internal/store"
	"nexus-perm/internal/sync"
)

type Server struct {
	st      *store.Store
	engine  *sync.Engine
	authSvc *auth.Service
	guard   *loginGuard
}

func NewServer(st *store.Store, authSvc *auth.Service) *Server {
	return &Server{st: st, engine: sync.NewEngine(st), authSvc: authSvc, guard: newLoginGuard()}
}

func (s *Server) Register(r *gin.Engine) {
	api := r.Group("/api")

	// 免登录接口：只有登录本身
	api.POST("/auth/login", s.login)

	// 以下全部需要登录（平台用户不分角色，登录即可用全部功能）
	a := api.Group("", s.authRequired())
	{
		a.POST("/auth/logout", s.logout)
		a.GET("/auth/me", s.me)
		a.PUT("/auth/password", s.changePassword)

		a.GET("/platform-users", s.listPlatformUsers)
		a.POST("/platform-users", s.createPlatformUser)
		a.PUT("/platform-users/:id", s.updatePlatformUser)
		a.DELETE("/platform-users/:id", s.deletePlatformUser)
		a.PUT("/platform-users/:id/password", s.resetPlatformUserPassword)
		a.GET("/login-logs", s.listLoginLogs)

		a.GET("/instances", s.listInstances)
		a.POST("/instances", s.createInstance)
		a.DELETE("/instances/:id", s.deleteInstance)
		a.POST("/instances/:id/test", s.testInstance)

		a.GET("/repos", s.listRepos)
		a.POST("/repos/refresh", s.refreshRepos)

		a.GET("/users", s.listUsers)
		a.POST("/users", s.createUser)
		a.PUT("/users/:id", s.updateUser)
		a.DELETE("/users/:id", s.deleteUser)
		a.POST("/users/import", s.importUsers)

		a.GET("/matrix", s.getMatrix)
		a.PUT("/matrix", s.setMatrixCell)

		a.GET("/templates", s.listTemplates)
		a.POST("/templates", s.saveTemplate)
		a.DELETE("/templates/:id", s.deleteTemplate)
		a.POST("/templates/:id/apply", s.applyTemplate)

		a.GET("/sync/diff", s.syncDiff)
		a.POST("/sync/apply", s.syncApply)
		a.PUT("/settings/anonymous", s.setAnonymous)
		a.GET("/settings/anonymous", s.getAnonymous)

		a.GET("/audit", s.listAudit)
	}
}

func fail(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
}

func idParam(c *gin.Context) (int64, error) {
	return strconv.ParseInt(c.Param("id"), 10, 64)
}

// ---------------- 实例 ----------------

func (s *Server) listInstances(c *gin.Context) {
	list, err := s.st.ListInstances()
	if err != nil {
		fail(c, err)
		return
	}
	if list == nil {
		list = []store.Instance{}
	}
	c.JSON(http.StatusOK, gin.H{"instances": list})
}

type instanceReq struct {
	Name      string `json:"name" binding:"required"`
	BaseURL   string `json:"base_url" binding:"required"`
	AdminUser string `json:"admin_user" binding:"required"`
	AdminPass string `json:"admin_pass" binding:"required"`
}

func (s *Server) createInstance(c *gin.Context) {
	var req instanceReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, err)
		return
	}
	id, err := s.st.CreateInstance(req.Name, req.BaseURL, req.AdminUser, req.AdminPass)
	if err != nil {
		fail(c, err)
		return
	}
	_ = s.st.AddAudit("instance", req.Name, req.BaseURL, "created")
	c.JSON(http.StatusOK, gin.H{"id": id})
}

func (s *Server) deleteInstance(c *gin.Context) {
	id, err := idParam(c)
	if err != nil {
		fail(c, err)
		return
	}
	if err := s.st.DeleteInstance(id); err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) testInstance(c *gin.Context) {
	id, err := idParam(c)
	if err != nil {
		fail(c, err)
		return
	}
	inst, err := s.st.GetInstance(id)
	if err != nil {
		fail(c, err)
		return
	}
	cli := nexus.NewClient(inst.BaseURL, inst.AdminUser, inst.AdminPass)
	status, err := cli.Check()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "status": status})
}

// ---------------- 仓库 ----------------

// ---------------- 仓库（只读缓存） ----------------

type simpleErr struct{ msg string }

func (e *simpleErr) Error() string { return e.msg }

func (s *Server) listRepos(c *gin.Context) {
	instID, err := strconv.ParseInt(c.Query("instance_id"), 10, 64)
	if err != nil {
		fail(c, err)
		return
	}
	repos, err := s.st.ListRepos(instID)
	if err != nil {
		fail(c, err)
		return
	}
	if repos == nil {
		repos = []store.Repo{}
	}
	c.JSON(http.StatusOK, gin.H{"repos": repos})
}

// refreshRepos 从 Nexus 拉取仓库列表，刷新本地缓存。
// 仓库是只读镜像：本工具不创建、不修改、不删除 Nexus 仓库，
// 缓存仅作为权限矩阵的数据源。
func (s *Server) refreshRepos(c *gin.Context) {
	instID, err := strconv.ParseInt(c.Query("instance_id"), 10, 64)
	if err != nil {
		fail(c, err)
		return
	}
	inst, err := s.st.GetInstance(instID)
	if err != nil {
		fail(c, err)
		return
	}
	cli := nexus.NewClient(inst.BaseURL, inst.AdminUser, inst.AdminPass)

	nxRepos, err := cli.ListRepositories()
	if err != nil {
		fail(c, err)
		return
	}

	local, err := s.st.ListRepos(instID)
	if err != nil {
		fail(c, err)
		return
	}
	have := map[string]bool{}
	for _, r := range local {
		have[r.Name] = true
	}
	nxNames := map[string]bool{}
	added := 0
	for _, r := range nxRepos {
		nxNames[r.Name] = true
		if !have[r.Name] {
			if err := s.st.UpsertRepo(instID, r.Name, r.Format, r.Type, ""); err != nil {
				fail(c, err)
				return
			}
			added++
		}
	}
	// 清掉 Nexus 上已不存在的缓存项（连同矩阵中引用它的权限）
	removed := 0
	for _, r := range local {
		if !nxNames[r.Name] {
			if err := s.st.DeleteRepo(instID, r.Name); err != nil {
				fail(c, err)
				return
			}
			removed++
		}
	}
	_ = s.st.AddAudit("repo-refresh", inst.Name,
		fmt.Sprintf("新增 %d，移除 %d，共 %d", added, removed, len(nxRepos)), "done")
	c.JSON(http.StatusOK, gin.H{"ok": true, "added": added, "removed": removed, "total": len(nxRepos)})
}

// ---------------- 用户 ----------------

func (s *Server) listUsers(c *gin.Context) {
	instID, err := strconv.ParseInt(c.Query("instance_id"), 10, 64)
	if err != nil {
		fail(c, err)
		return
	}
	users, err := s.st.ListUsers(instID)
	if err != nil {
		fail(c, err)
		return
	}
	if users == nil {
		users = []store.User{}
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

type userReq struct {
	InstanceID int64  `json:"instance_id"`
	Username   string `json:"username" binding:"required"`
	Email      string `json:"email"`
	Password   string `json:"password"`
}

func (s *Server) createUser(c *gin.Context) {
	var req userReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, err)
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		fail(c, &simpleErr{"用户名不能为空"})
		return
	}
	id, err := s.st.CreateUser(req.InstanceID, req.Username, req.Email, req.Password)
	if err != nil {
		fail(c, err)
		return
	}
	_ = s.st.AddAudit("user", req.Username, req.Email, "declared")
	c.JSON(http.StatusOK, gin.H{"id": id})
}

type userUpdateReq struct {
	Email    *string `json:"email"`
	Password *string `json:"password"`
	Enabled  *bool   `json:"enabled"`
}

func (s *Server) updateUser(c *gin.Context) {
	id, err := idParam(c)
	if err != nil {
		fail(c, err)
		return
	}
	var req userUpdateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, err)
		return
	}
	if err := s.st.UpdateUser(id, req.Email, req.Password, req.Enabled); err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) deleteUser(c *gin.Context) {
	id, err := idParam(c)
	if err != nil {
		fail(c, err)
		return
	}
	u, err := s.st.GetUser(id)
	if err != nil {
		fail(c, err)
		return
	}
	if err := s.st.DeleteUser(id); err != nil {
		fail(c, err)
		return
	}
	_ = s.st.AddAudit("user", u.Username, "", "deleted")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ---------------- 权限矩阵 ----------------

type matrixResp struct {
	Repos []store.Repo `json:"repos"`
	Users []store.User `json:"users"`
}

func (s *Server) getMatrix(c *gin.Context) {
	instID, err := strconv.ParseInt(c.Query("instance_id"), 10, 64)
	if err != nil {
		fail(c, err)
		return
	}
	repos, err := s.st.ListRepos(instID)
	if err != nil {
		fail(c, err)
		return
	}
	users, err := s.st.ListUsers(instID)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, matrixResp{Repos: repos, Users: users})
}

type matrixReq struct {
	UserID int64  `json:"user_id"`
	Repo   string `json:"repo" binding:"required"`
	Level  string `json:"level"` // ro/upload/full，空 = 清除
}

func (s *Server) setMatrixCell(c *gin.Context) {
	var req matrixReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, err)
		return
	}
	if req.Level != "" && !nexus.ValidLevel(req.Level) {
		fail(c, &simpleErr{"非法权限级别: " + req.Level})
		return
	}
	if err := s.st.SetPermission(req.UserID, req.Repo, req.Level); err != nil {
		fail(c, err)
		return
	}
	// 矩阵变更必须留痕：否则权限被误改后无法追溯
	if u, err := s.st.GetUser(req.UserID); err == nil {
		_ = s.st.AddAudit("matrix", u.Username+" -> "+req.Repo, "level="+req.Level, "updated")
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ---------------- 模板 ----------------

func (s *Server) listTemplates(c *gin.Context) {
	instID, err := strconv.ParseInt(c.Query("instance_id"), 10, 64)
	if err != nil {
		fail(c, err)
		return
	}
	tpls, err := s.st.ListTemplates(instID)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"templates": tpls})
}

type templateReq struct {
	InstanceID int64   `json:"instance_id"`
	Name       string  `json:"name" binding:"required"`
	MatchType  string  `json:"match_type" binding:"required"` // prefix / format / explicit
	MatchValue string  `json:"match_value"`
	Level      string  `json:"level" binding:"required"`
	UserIDs    []int64 `json:"user_ids"`
}

func (s *Server) saveTemplate(c *gin.Context) {
	var req templateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, err)
		return
	}
	if req.MatchType != "prefix" && req.MatchType != "format" && req.MatchType != "explicit" {
		fail(c, &simpleErr{"匹配类型只支持 prefix/format/explicit"})
		return
	}
	if !nexus.ValidLevel(req.Level) {
		fail(c, &simpleErr{"非法权限级别: " + req.Level})
		return
	}
	id, err := s.st.UpsertTemplate(req.InstanceID, req.Name, req.MatchType, req.MatchValue, req.Level, req.UserIDs)
	if err != nil {
		fail(c, err)
		return
	}
	_ = s.st.AddAudit("template", req.Name, req.MatchType+"="+req.MatchValue+" level="+req.Level, "saved")
	c.JSON(http.StatusOK, gin.H{"id": id})
}

func (s *Server) deleteTemplate(c *gin.Context) {
	id, err := idParam(c)
	if err != nil {
		fail(c, err)
		return
	}
	tpl, err := s.st.GetTemplate(id)
	if err != nil {
		fail(c, err)
		return
	}
	if err := s.st.DeleteTemplate(id); err != nil {
		fail(c, err)
		return
	}
	_ = s.st.AddAudit("template", tpl.Name, "", "deleted")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type applyTemplateReq struct {
	UserIDs []int64 `json:"user_ids"` // 为空则套用到模板已绑定的全部用户
}

// applyTemplate 把模板展开为逐仓库权限写入矩阵（只增不删，不影响用户已有的其他仓库权限）。
func (s *Server) applyTemplate(c *gin.Context) {
	id, err := idParam(c)
	if err != nil {
		fail(c, err)
		return
	}
	var req applyTemplateReq
	_ = c.ShouldBindJSON(&req)

	tpl, err := s.st.GetTemplate(id)
	if err != nil {
		fail(c, err)
		return
	}
	repos, err := s.st.ListRepos(tpl.InstanceID)
	if err != nil {
		fail(c, err)
		return
	}
	matched := tpl.MatchRepos(repos)
	if len(matched) == 0 {
		fail(c, &simpleErr{"模板没有匹配到任何仓库，请检查匹配规则"})
		return
	}

	userIDs := req.UserIDs
	if len(userIDs) == 0 {
		userIDs = tpl.UserIDs
	}
	if len(userIDs) == 0 {
		fail(c, &simpleErr{"模板没有绑定用户"})
		return
	}
	users, err := s.st.ListUsers(tpl.InstanceID)
	if err != nil {
		fail(c, err)
		return
	}
	valid := map[int64]bool{}
	for _, u := range users {
		valid[u.ID] = true
	}
	applied := 0
	for _, uid := range userIDs {
		if !valid[uid] {
			continue
		}
		for _, repo := range matched {
			if err := s.st.SetPermission(uid, repo, tpl.Level); err != nil {
				fail(c, err)
				return
			}
			applied++
		}
	}
	_ = s.st.AddAudit("template-apply", tpl.Name,
		fmt.Sprintf("%d 个仓库 x %d 个用户 = %d 条权限", len(matched), len(userIDs), applied), "done")
	c.JSON(http.StatusOK, gin.H{
		"ok":              true,
		"matched_repos":   len(matched),
		"applied_cells":   applied,
		"matched_repo_names": matched,
	})
}

// ---------------- 同步 ----------------

func (s *Server) syncDiff(c *gin.Context) {
	instID, err := strconv.ParseInt(c.Query("instance_id"), 10, 64)
	if err != nil {
		fail(c, err)
		return
	}
	inst, err := s.st.GetInstance(instID)
	if err != nil {
		fail(c, err)
		return
	}
	diff, err := s.engine.ComputeDiff(inst)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, diff)
}

type applyReq struct {
	InstanceID       int64 `json:"instance_id"`
	DeleteExtraUsers bool `json:"delete_extra_users"`
	DeleteExtraRoles bool `json:"delete_extra_roles"`
}

func (s *Server) syncApply(c *gin.Context) {
	var req applyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, err)
		return
	}
	inst, err := s.st.GetInstance(req.InstanceID)
	if err != nil {
		fail(c, err)
		return
	}
	results, err := s.engine.Apply(inst, sync.ApplyOpts{
		DeleteExtraUsers: req.DeleteExtraUsers,
		DeleteExtraRoles: req.DeleteExtraRoles,
	})
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": results})
}

type anonReq struct {
	InstanceID int64 `json:"instance_id"`
	Enabled    bool  `json:"enabled"`
}

func (s *Server) getAnonymous(c *gin.Context) {
	instID, err := strconv.ParseInt(c.Query("instance_id"), 10, 64)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": s.st.GetAnonymousSetting(instID)})
}

func (s *Server) setAnonymous(c *gin.Context) {
	var req anonReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, err)
		return
	}
	if err := s.st.SetAnonymousSetting(req.InstanceID, req.Enabled); err != nil {
		fail(c, err)
		return
	}
	_ = s.st.AddAudit("settings", "anonymous", strconv.FormatBool(req.Enabled), "updated")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ---------------- 导入 ----------------

type importReq struct {
	InstanceID int64 `json:"instance_id"`
}

// importUsers 把 Nexus 上已有的用户导入本地（用于从已有环境起步）。
// 密码未知 -> 空密码记录，仅用于角色绑定管理，不会尝试改密码。
func (s *Server) importUsers(c *gin.Context) {
	var req importReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, err)
		return
	}
	inst, err := s.st.GetInstance(req.InstanceID)
	if err != nil {
		fail(c, err)
		return
	}
	cli := nexus.NewClient(inst.BaseURL, inst.AdminUser, inst.AdminPass)

	nxUsers, err := cli.ListUsers()
	if err != nil {
		fail(c, err)
		return
	}
	localUsers, err := s.st.ListUsers(req.InstanceID)
	if err != nil {
		fail(c, err)
		return
	}
	haveU := map[string]bool{}
	for _, u := range localUsers {
		haveU[u.Username] = true
	}
	imported := 0
	for _, u := range nxUsers {
		if u.UserID == "admin" || u.UserID == "anonymous" || haveU[u.UserID] {
			continue
		}
		if _, err := s.st.CreateUser(req.InstanceID, u.UserID, u.EmailAddress, ""); err != nil {
			fail(c, err)
			return
		}
		imported++
	}
	_ = s.st.AddAudit("user-import", inst.Name, "users="+strconv.Itoa(imported), "done")
	c.JSON(http.StatusOK, gin.H{"ok": true, "imported_users": imported})
}

// ---------------- 审计 ----------------

func (s *Server) listAudit(c *gin.Context) {
	logs, err := s.st.ListAudit(200)
	if err != nil {
		fail(c, err)
		return
	}
	if logs == nil {
		logs = []store.AuditLog{}
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs})
}
