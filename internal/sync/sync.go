package sync

import (
	"fmt"
	"sort"
	"strings"

	"nexus-perm/internal/nexus"
	"nexus-perm/internal/store"
)

// Engine 把本地"意图状态"（store）同步到 Nexus 实际状态。
type Engine struct {
	st *store.Store
}

func NewEngine(st *store.Store) *Engine { return &Engine{st: st} }

// PlannedAction 一条计划中的变更。
type PlannedAction struct {
	Kind   string `json:"kind"`   // repo_create/user_create/user_update/role_create/role_update/anon_set
	Target string `json:"target"` // 对象名
	Detail string `json:"detail"` // 人类可读说明
	// Changes 逐仓库的权限级别变化（From = Nexus 当前级别，To = 本地目标级别；"" 表示无权限）
	Changes []LevelChange `json:"changes,omitempty"`
	// RemovedExtra PUT 完整权限列表时会被清掉的角色额外权限（非本工具管理的权限）
	RemovedExtra []string `json:"removed_extra,omitempty"`
}

// LevelChange 单个仓库的权限级别变化。
type LevelChange struct {
	Repo string `json:"repo"`
	From string `json:"from"`
	To   string `json:"to"`
}

var repoActions = []string{"read", "browse", "edit", "add", "delete"}

// deriveLevel 从 Nexus 角色的权限列表反推某仓库的权限级别。
func deriveLevel(have map[string]bool, format, repo string) string {
	pf := nexus.PrivFormat(format)
	prefix := "nx-repository-view-" + pf + "-" + repo + "-"
	has := func(a string) bool { return have[prefix+a] }
	switch {
	case has("read") && has("browse") && has("edit") && has("add") && has("delete"):
		return nexus.LevelFull
	case has("read") && has("browse") && has("edit") && has("add"):
		return nexus.LevelUpload
	case has("read") && has("browse"):
		return nexus.LevelRO
	}
	for _, a := range repoActions {
		if has(a) {
			return "部分"
		}
	}
	return ""
}

// targetChanges 本地目标展开为逐仓库级别变化（From 为空表示新建）。
func targetChanges(perms map[string]string, d *desired) []LevelChange {
	var out []LevelChange
	for _, r := range d.repos {
		if lv := perms[r.Name]; lv != "" {
			out = append(out, LevelChange{Repo: r.Name, From: "", To: lv})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out
}

// diffLevels 对比 Nexus 实际权限与本地目标矩阵，产出逐仓库级别变化，
// 以及会被"PUT 完整列表"清掉的额外权限。
func diffLevels(actualPrivs []string, perms map[string]string, d *desired) (changes []LevelChange, removedExtra []string) {
	have := map[string]bool{}
	for _, p := range actualPrivs {
		have[p] = true
	}
	wantSet := map[string]bool{}
	for _, p := range nexus.BuildRolePrivileges(perms, d.repoFormat) {
		wantSet[p] = true
	}
	known := map[string]bool{}
	for _, p := range nexus.GlobalPrivileges {
		known[p] = true
	}
	for _, r := range d.repos {
		pf := nexus.PrivFormat(r.Format)
		for _, a := range repoActions {
			known["nx-repository-view-"+pf+"-"+r.Name+"-"+a] = true
		}
		from := deriveLevel(have, r.Format, r.Name)
		to := perms[r.Name]
		if from != to {
			changes = append(changes, LevelChange{Repo: r.Name, From: from, To: to})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Repo < changes[j].Repo })
	for p := range have {
		if !wantSet[p] && !known[p] {
			removedExtra = append(removedExtra, p)
		}
	}
	sort.Strings(removedExtra)
	return changes, removedExtra
}

// ExtraItem Nexus 上存在但本地未声明的对象（默认不动，仅在 apply 勾选后删除）。
type ExtraItem struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

type Diff struct {
	Actions  []PlannedAction `json:"actions"`
	Extras   []ExtraItem     `json:"extras"`
	Warnings []string        `json:"warnings"`
}

// desired 本地推导出的目标状态。
type desired struct {
	repos       []store.Repo
	users       []store.User
	repoFormat  map[string]string
	repoByName  map[string]store.Repo
	anon        bool
}

func (e *Engine) loadDesired(instanceID int64) (*desired, error) {
	repos, err := e.st.ListRepos(instanceID)
	if err != nil {
		return nil, err
	}
	users, err := e.st.ListUsers(instanceID)
	if err != nil {
		return nil, err
	}
	d := &desired{
		repos:      repos,
		users:      users,
		repoFormat: map[string]string{},
		repoByName: map[string]store.Repo{},
		anon:       e.st.GetAnonymousSetting(instanceID),
	}
	for _, r := range repos {
		d.repoFormat[r.Name] = r.Format
		d.repoByName[r.Name] = r
	}
	return d, nil
}

// ComputeDiff 对比本地意图与 Nexus 实际状态，产出执行计划（不修改任何东西）。
func (e *Engine) ComputeDiff(inst *store.Instance) (*Diff, error) {
	cli := nexus.NewClient(inst.BaseURL, inst.AdminUser, inst.AdminPass)
	d, err := e.loadDesired(inst.ID)
	if err != nil {
		return nil, err
	}

	nxRepos, err := cli.ListRepositories()
	if err != nil {
		return nil, err
	}
	nxUsers, err := cli.ListUsers()
	if err != nil {
		return nil, err
	}
	nxRoles, err := cli.ListRoles()
	if err != nil {
		return nil, err
	}

	actualRepos := map[string]nexus.NXRepo{}
	for _, r := range nxRepos {
		actualRepos[r.Name] = r
	}
	actualUsers := map[string]nexus.NXUser{}
	for _, u := range nxUsers {
		actualUsers[u.UserID] = u
	}
	actualRoles := map[string]nexus.NXRole{}
	for _, r := range nxRoles {
		actualRoles[r.ID] = r
	}

	diff := &Diff{Actions: []PlannedAction{}, Extras: []ExtraItem{}, Warnings: []string{}}

	for _, u := range d.users {
		roleID := nexus.RoleIDForUser(u.Username)
		wantPrivs := nexus.BuildRolePrivileges(u.Perms, d.repoFormat)
		wantRoles := []string{roleID}

		nxUser, userExists := actualUsers[u.Username]
		if !userExists {
			if u.Password == "" {
				diff.Warnings = append(diff.Warnings,
					fmt.Sprintf("用户 %s 在 Nexus 不存在且本地未保存密码，apply 将跳过创建", u.Username))
			} else {
				detail := fmt.Sprintf("创建用户并绑定角色 %s", roleID)
				if !u.Enabled {
					detail += "（状态：停用）"
				}
				diff.Actions = append(diff.Actions, PlannedAction{
					Kind:    "user_create",
					Target:  u.Username,
					Detail:  detail,
					Changes: targetChanges(u.Perms, d),
				})
			}
		} else {
			if !sameStrings(nxUser.Roles, wantRoles) {
				diff.Actions = append(diff.Actions, PlannedAction{
					Kind:   "user_update",
					Target: u.Username,
					Detail: fmt.Sprintf("更新角色绑定: %v -> %v", nxUser.Roles, wantRoles),
				})
			}
			// 启停状态同步（Nexus status: active/disabled）
			if u.Enabled != (nxUser.Status == "active") {
				from := firstNonEmptyStr(nxUser.Status, "active")
				to := "active"
				if !u.Enabled {
					to = "disabled"
				}
				diff.Actions = append(diff.Actions, PlannedAction{
					Kind:   "user_status",
					Target: u.Username,
					Detail: fmt.Sprintf("账号状态: %s -> %s", from, to),
				})
			}
			if u.PasswordDirty {
				// 本地改过密码：Nexus 的更新接口不接受 password 字段，需删除重建
				diff.Actions = append(diff.Actions, PlannedAction{
					Kind:   "user_password",
					Target: u.Username,
					Detail: "更新 Nexus 登录密码（删除重建方式，角色权限不受影响）",
				})
			}
		}

		nxRole, roleExists := actualRoles[roleID]
		if !roleExists {
			diff.Actions = append(diff.Actions, PlannedAction{
				Kind:    "role_create",
				Target:  roleID,
				Detail:  fmt.Sprintf("创建角色，%d 个权限", len(wantPrivs)),
				Changes: targetChanges(u.Perms, d),
			})
		} else if !sameStringSets(nxRole.Privileges, wantPrivs) {
			changes, removedExtra := diffLevels(nxRole.Privileges, u.Perms, d)
			diff.Actions = append(diff.Actions, PlannedAction{
				Kind:         "role_update",
				Target:       roleID,
				Detail:       fmt.Sprintf("权限差异: Nexus %d 个 -> 目标 %d 个", len(nxRole.Privileges), len(wantPrivs)),
				Changes:      changes,
				RemovedExtra: removedExtra,
			})
		}
	}

	nxAnon, err := cli.GetAnonymous()
	if err != nil {
		return nil, err
	}
	if nxAnon != d.anon {
		state := "开启"
		if !d.anon {
			state = "关闭"
		}
		diff.Actions = append(diff.Actions, PlannedAction{
			Kind:   "anon_set",
			Target: "anonymous",
			Detail: fmt.Sprintf("匿名访问设置为 %s（当前 %v）", state, nxAnon),
		})
	}

	// 仓库为只读镜像（本地缓存即 Nexus 现状），不存在"多余仓库"概念
	desiredUsers := map[string]bool{}
	for _, u := range d.users {
		desiredUsers[u.Username] = true
	}
	for id := range actualUsers {
		if !desiredUsers[id] && id != "admin" && id != "anonymous" {
			diff.Extras = append(diff.Extras, ExtraItem{Kind: "user", Target: id})
		}
	}
	// 自定义角色识别：Nexus 内置角色一律 nx- 前缀；source 字段不可靠（自定义角色也是 default）。
	for id := range actualRoles {
		if strings.HasPrefix(id, "nx-") || isManagedRole(id, d) {
			continue
		}
		diff.Extras = append(diff.Extras, ExtraItem{Kind: "role", Target: id})
	}
	sort.Slice(diff.Extras, func(i, j int) bool {
		if diff.Extras[i].Kind != diff.Extras[j].Kind {
			return diff.Extras[i].Kind < diff.Extras[j].Kind
		}
		return diff.Extras[i].Target < diff.Extras[j].Target
	})

	diff.Warnings = append(diff.Warnings, groupWarnings(d)...)

	return diff, nil
}

// ApplyOpts apply 选项：是否删除 Nexus 上多出的用户/角色（仓库只读，不涉及）。
type ApplyOpts struct {
	DeleteExtraUsers bool
	DeleteExtraRoles bool
}

// ActionResult 单步执行结果。
type ActionResult struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	OK     bool   `json:"ok"`
	Err    string `json:"err,omitempty"`
}

// Apply 执行下发（幂等，可重复执行）。
func (e *Engine) Apply(inst *store.Instance, opts ApplyOpts) ([]ActionResult, error) {
	cli := nexus.NewClient(inst.BaseURL, inst.AdminUser, inst.AdminPass)
	d, err := e.loadDesired(inst.ID)
	if err != nil {
		return nil, err
	}

	nxUsers, err := cli.ListUsers()
	if err != nil {
		return nil, err
	}
	nxRoles, err := cli.ListRoles()
	if err != nil {
		return nil, err
	}
	actualUsers := map[string]nexus.NXUser{}
	for _, u := range nxUsers {
		actualUsers[u.UserID] = u
	}
	actualRoles := map[string]nexus.NXRole{}
	for _, r := range nxRoles {
		actualRoles[r.ID] = r
	}

	var results []ActionResult
	record := func(kind, target string, err error) {
		r := ActionResult{Kind: kind, Target: target, OK: err == nil}
		if err != nil {
			r.Err = err.Error()
		}
		results = append(results, r)
		res := "OK"
		if err != nil {
			res = "FAIL: " + err.Error()
		}
		_ = e.st.AddAudit("apply:"+kind, target, "", res)
	}

	// 1) 角色（先于用户：用户绑定的角色必须存在；仓库为只读，不在此创建）
	for _, u := range d.users {
		roleID := nexus.RoleIDForUser(u.Username)
		wantPrivs := nexus.BuildRolePrivileges(u.Perms, d.repoFormat)
		nxRole, exists := actualRoles[roleID]
		if !exists || !sameStringSets(nxRole.Privileges, wantPrivs) {
			kind := "role_update"
			if !exists {
				kind = "role_create"
			}
			err := cli.PutRole(nexus.NXRole{
				ID:          roleID,
				Name:        roleID,
				Description: fmt.Sprintf("auto role for user %s (nexus-perm)", u.Username),
				Privileges:  wantPrivs,
			})
			record(kind, roleID, err)
		}
	}

	// 2) 用户
	for _, u := range d.users {
		roleID := nexus.RoleIDForUser(u.Username)
		nxUser, exists := actualUsers[u.Username]
		if !exists {
			if u.Password == "" {
				record("user_create", u.Username, fmt.Errorf("本地未保存密码，跳过（请编辑用户补密码）"))
				continue
			}
			status := "active"
			if !u.Enabled {
				status = "disabled"
			}
			err := cli.CreateUser(nexus.NXUser{
				UserID:       u.Username,
				EmailAddress: u.Email,
				Status:       status,
				Roles:        []string{roleID},
			}, u.Password)
			record("user_create", u.Username, err)
			continue
		}
		if !sameStrings(nxUser.Roles, []string{roleID}) {
			nxUser.Roles = []string{roleID}
			err := cli.UpdateUser(nxUser)
			record("user_update", u.Username, err)
		}
		// 启停状态同步
		if u.Enabled != (nxUser.Status == "active") {
			nxUser.Status = "active"
			if !u.Enabled {
				nxUser.Status = "disabled"
			}
			err := cli.UpdateUser(nxUser)
			record("user_status", u.Username, err)
		}
		// 密码待同步：Nexus 更新接口不接受 password 字段（实测 PUT 静默忽略），
		// 唯一可靠的 REST 方式是删除后以新密码重建（角色已在上面绑定/保持不变）。
		if u.PasswordDirty {
			if err := cli.DeleteUser(u.Username); err != nil {
				record("user_password", u.Username, err)
				continue
			}
			err := cli.CreateUser(nexus.NXUser{
				UserID:       u.Username,
				EmailAddress: u.Email,
				Roles:        []string{roleID},
			}, u.Password)
			if err != nil {
				record("user_password", u.Username, err)
				continue
			}
			_ = e.st.ClearUserPasswordDirty(u.ID)
			record("user_password", u.Username, nil)
		}
	}

	// 3) 匿名访问
	nxAnon, err := cli.GetAnonymous()
	if err != nil {
		return nil, err
	}
	if nxAnon != d.anon {
		err := cli.SetAnonymous(d.anon)
		record("anon_set", "anonymous", err)
	}

	// 4) 可选：删除 Nexus 上多出的用户/角色（仓库只读，不删）
	desiredUsers := map[string]bool{}
	for _, u := range d.users {
		desiredUsers[u.Username] = true
	}
	if opts.DeleteExtraUsers {
		for id := range actualUsers {
			if !desiredUsers[id] && id != "admin" && id != "anonymous" {
				err := cli.DeleteUser(id)
				record("user_delete", id, err)
			}
		}
	}
	if opts.DeleteExtraRoles {
		for id, r := range actualRoles {
			if r.Source == "default" || id == "nx-anonymous" || isManagedRole(id, d) {
				continue
			}
			err := cli.DeleteRole(id)
			record("role_delete", id, err)
		}
	}

	_ = e.st.AddAudit("apply", inst.Name, fmt.Sprintf("%d 步操作", len(results)), "done")
	return results, nil
}

// groupWarnings group 仓库的授权注意事项（实测结论）。
// 注意：Nexus 3.49 的 REST API 不返回 group 成员列表（GET /repositories/{name}
// 只有摘要，extdirect 在 OSS 版不可用），无法精确校验成员授权，故给通用告警。
func groupWarnings(d *desired) []string {
	var warns []string
	for _, u := range d.users {
		for repo, level := range u.Perms {
			r, ok := d.repoByName[repo]
			if !ok || r.Type != "group" || !nexus.ValidLevel(level) {
				continue
			}
			if level != nexus.LevelRO {
				warns = append(warns, fmt.Sprintf(
					"用户 %s 对 group %s 授予 %s：group 结构上只读，上传/删除会 403，建议改 ro",
					u.Username, repo, level))
			}
			warns = append(warns, fmt.Sprintf(
				"用户 %s 对 group %s 授予 %s：访问 group 需要对其所有成员仓库都有 read 权限（实测），若下载 403 请逐一检查成员仓库授权",
				u.Username, repo, level))
		}
	}
	return warns
}

// isManagedRole 是否是本工具管理的自动角色（user-<用户名>）。
func isManagedRole(id string, d *desired) bool {
	for _, u := range d.users {
		if nexus.RoleIDForUser(u.Username) == id {
			return true
		}
	}
	return false
}

func firstNonEmptyStr(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]string{}, a...)
	sb := append([]string{}, b...)
	sort.Strings(sa)
	sort.Strings(sb)
	return sameStrings(sa, sb)
}
