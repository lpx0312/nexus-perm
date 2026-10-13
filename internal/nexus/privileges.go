package nexus

import "fmt"

// 权限级别（与 nexus-permission-setup.sh 一致）：
//
//	ro      只读           = read + browse
//	upload  只读 + 上传     = read + browse + edit + add
//	full    读写 + 删除     = read + browse + edit + add + delete
//
// 实测结论（Nexus 3.49）：
//   - mvn deploy / npm publish / curl PUT 等 HTTP PUT 上传校验的是 edit，
//     仅 add 会被 403；add 只对 UI Upload 端点生效。
//     所以 upload 档必须含 edit，才能覆盖全部上传通道且删除一律 403。
const (
	LevelRO     = "ro"
	LevelUpload = "upload"
	LevelFull   = "full"
)

// GlobalPrivileges 每个用户角色自动附加的全局权限：
//   - nx-search-read      UI/API 搜索能力
//   - nx-component-upload Nexus 3.49 前端 Upload 菜单入口（无此前端不显示上传页）
var GlobalPrivileges = []string{"nx-search-read", "nx-component-upload"}

var levelActions = map[string][]string{
	LevelRO:     {"read", "browse"},
	LevelUpload: {"read", "browse", "edit", "add"},
	LevelFull:   {"read", "browse", "edit", "add", "delete"},
}

func ValidLevel(level string) bool {
	_, ok := levelActions[level]
	return ok
}

// PrivFormat 仓库 API 用的格式 -> 权限名用的格式（maven -> maven2）。
func PrivFormat(format string) string {
	if format == "maven" {
		return "maven2"
	}
	return format
}

// ExpandPrivileges 展开"用户对某仓库的权限级别"为 Nexus 权限名列表。
func ExpandPrivileges(level, format, repo string) []string {
	acts, ok := levelActions[level]
	if !ok {
		return nil
	}
	pf := PrivFormat(format)
	out := make([]string, 0, len(acts))
	for _, a := range acts {
		out = append(out, fmt.Sprintf("nx-repository-view-%s-%s-%s", pf, repo, a))
	}
	return out
}

// RoleIDForUser 每用户一个自动角色。
func RoleIDForUser(username string) string {
	return "user-" + username
}

// BuildRolePrivileges 由权限矩阵推导某用户的完整 Nexus 权限列表（去重、排序稳定）。
//   - perms: 仓库名 -> 权限级别
//   - repoFormats: 仓库名 -> 仓库格式（用于 maven2 映射）
func BuildRolePrivileges(perms map[string]string, repoFormats map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for repo, level := range perms {
		for _, p := range ExpandPrivileges(level, repoFormats[repo], repo) {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	for _, p := range GlobalPrivileges {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
