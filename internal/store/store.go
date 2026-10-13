package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Instance 一个 Nexus 实例（地址 + admin 凭据，凭据加密存储）。
type Instance struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	BaseURL   string `json:"base_url"`
	AdminUser string `json:"admin_user"`
	AdminPass string `json:"-"` // 解密后的明文，仅运行时使用，不序列化
}

// Repo 本地声明的仓库意图。
// Param 含义按 Type 区分：
//   - hosted: maven 版本策略(RELEASE/SNAPSHOT/MIXED)，其他格式填 "-"
//   - proxy : 远程仓库地址
//   - group : 成员仓库名(逗号分隔)
type Repo struct {
	ID         int64  `json:"id"`
	InstanceID int64  `json:"instance_id"`
	Name       string `json:"name"`
	Format     string `json:"format"` // maven / npm / ...
	Type       string `json:"type"`   // hosted / proxy / group
	Param      string `json:"param"`
}

// User 本地声明的用户；Perms 为 仓库名 -> 权限级别(ro/upload/full)。
// PasswordDirty 表示本地改过密码但尚未推送到 Nexus（Nexus 的更新接口
// 不接受 password 字段，推送时走"删除重建"）。
type User struct {
	ID            int64             `json:"id"`
	InstanceID    int64             `json:"instance_id"`
	Username      string            `json:"username"`
	Email         string            `json:"email"`
	Enabled       bool              `json:"enabled"`
	Password      string            `json:"-"`
	PasswordDirty bool              `json:"password_dirty"`
	Perms         map[string]string `json:"perms"`
}

// PlatformUser 平台自身用户（登录用），不分角色——登录即可使用全部功能。
type PlatformUser struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Email        string `json:"email"`
	Enabled      bool   `json:"enabled"`
	CreatedAt    string `json:"created_at"`
	LastLoginAt  string `json:"last_login_at"`
}

type LoginLog struct {
	ID       int64  `json:"id"`
	TS       string `json:"ts"`
	Username string `json:"username"`
	IP       string `json:"ip"`
	Result   string `json:"result"` // success / failed
	Detail   string `json:"detail"`
}

type AuditLog struct {
	ID     int64  `json:"id"`
	TS     string `json:"ts"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail"`
	Result string `json:"result"`
}

// Template 权限模板：按匹配规则（前缀/格式/显式列表）批量定义一组仓库的权限级别，
// 套用到用户时展开为逐仓库权限。解决仓库数量多时逐格点击不可用的问题。
//   - prefix  : MatchValue = 仓库名前缀，如 maven-team-a-
//   - format  : MatchValue = 仓库格式，如 maven2 / npm
//   - explicit: MatchValue = 仓库名逗号分隔列表
type Template struct {
	ID         int64    `json:"id"`
	InstanceID int64    `json:"instance_id"`
	Name       string   `json:"name"`
	MatchType  string   `json:"match_type"`
	MatchValue string   `json:"match_value"`
	Level      string   `json:"level"`
	UserIDs    []int64  `json:"user_ids"`
	UserNames  []string `json:"user_names"`
}

// MatchRepos 返回模板匹配到的仓库名列表。
func (t *Template) MatchRepos(repos []Repo) []string {
	var out []string
	switch t.MatchType {
	case "prefix":
		for _, r := range repos {
			if len(t.MatchValue) > 0 && strings.HasPrefix(r.Name, t.MatchValue) {
				out = append(out, r.Name)
			}
		}
	case "format":
		for _, r := range repos {
			if r.Format == t.MatchValue {
				out = append(out, r.Name)
			}
		}
	case "explicit":
		for _, name := range splitAndTrim(t.MatchValue) {
			out = append(out, name)
		}
	}
	return out
}

type Store struct {
	db     *sql.DB
	crypto *Crypto
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	c, err := LoadCrypto(dir)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "nexus-perm.db"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite 单写者，避免 database is locked
	s := &Store{db: db, crypto: c}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS instances(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			base_url TEXT NOT NULL,
			admin_user TEXT NOT NULL,
			admin_pass_enc TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS repos(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			instance_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			format TEXT NOT NULL,
			type TEXT NOT NULL,
			param TEXT NOT NULL DEFAULT '',
			UNIQUE(instance_id, name)
		)`,
		`CREATE TABLE IF NOT EXISTS users(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			instance_id INTEGER NOT NULL,
			username TEXT NOT NULL,
			email TEXT NOT NULL DEFAULT '',
			password_enc TEXT NOT NULL DEFAULT '',
			password_dirty INTEGER NOT NULL DEFAULT 0,
			enabled INTEGER NOT NULL DEFAULT 1,
			UNIQUE(instance_id, username)
		)`,
		`CREATE TABLE IF NOT EXISTS permissions(
			user_id INTEGER NOT NULL,
			repo_name TEXT NOT NULL,
			level TEXT NOT NULL,
			PRIMARY KEY(user_id, repo_name)
		)`,
		`CREATE TABLE IF NOT EXISTS settings(
			instance_id INTEGER PRIMARY KEY,
			anonymous_enabled INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS platform_users(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			email TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			last_login_at TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS login_logs(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT NOT NULL,
			username TEXT NOT NULL DEFAULT '',
			ip TEXT NOT NULL DEFAULT '',
			result TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT NOT NULL,
			action TEXT NOT NULL,
			target TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT '',
			result TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS templates(
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			instance_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			match_type TEXT NOT NULL,
			match_value TEXT NOT NULL DEFAULT '',
			level TEXT NOT NULL,
			UNIQUE(instance_id, name)
		)`,
		`CREATE TABLE IF NOT EXISTS template_users(
			template_id INTEGER NOT NULL,
			user_id INTEGER NOT NULL,
			PRIMARY KEY(template_id, user_id)
		)`,
	}
	for _, st := range stmts {
		if _, err := s.db.Exec(st); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// 轻量列迁移：CREATE TABLE IF NOT EXISTS 不会给已存在的表补列
	for _, col := range []string{
		`ALTER TABLE users ADD COLUMN password_dirty INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := s.db.Exec(col); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// ---------------- Instance ----------------

func (s *Store) CreateInstance(name, baseURL, adminUser, adminPass string) (int64, error) {
	enc, err := s.crypto.Encrypt(adminPass)
	if err != nil {
		return 0, err
	}
	res, err := s.db.Exec(
		`INSERT INTO instances(name, base_url, admin_user, admin_pass_enc, created_at) VALUES(?,?,?,?,?)`,
		name, baseURL, adminUser, enc, time.Now().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	// 新实例默认匿名访问开启（Nexus 默认状态），用户可在同步页改
	_, _ = s.db.Exec(`INSERT OR IGNORE INTO settings(instance_id, anonymous_enabled) VALUES(?, 1)`, id)
	return id, nil
}

func (s *Store) ListInstances() ([]Instance, error) {
	rows, err := s.db.Query(`SELECT id, name, base_url, admin_user, admin_pass_enc FROM instances ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		var it Instance
		var enc string
		if err := rows.Scan(&it.ID, &it.Name, &it.BaseURL, &it.AdminUser, &enc); err != nil {
			return nil, err
		}
		if p, err := s.crypto.Decrypt(enc); err == nil {
			it.AdminPass = p
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *Store) GetInstance(id int64) (*Instance, error) {
	var it Instance
	var enc string
	err := s.db.QueryRow(
		`SELECT id, name, base_url, admin_user, admin_pass_enc FROM instances WHERE id = ?`, id).
		Scan(&it.ID, &it.Name, &it.BaseURL, &it.AdminUser, &enc)
	if err != nil {
		return nil, err
	}
	if p, err := s.crypto.Decrypt(enc); err == nil {
		it.AdminPass = p
	}
	return &it, nil
}

func (s *Store) DeleteInstance(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM instances WHERE id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM repos WHERE instance_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE instance_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM settings WHERE instance_id = ?`, id); err != nil {
		return err
	}
	// permissions 通过 user_id 关联，先找出该实例的用户再删
	if _, err := tx.Exec(`DELETE FROM permissions WHERE user_id IN (SELECT id FROM users WHERE instance_id = ?)`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM template_users WHERE template_id IN (SELECT id FROM templates WHERE instance_id = ?)`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM templates WHERE instance_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ---------------- Repo ----------------

func (s *Store) UpsertRepo(instanceID int64, name, format, typ, param string) error {
	_, err := s.db.Exec(
		`INSERT INTO repos(instance_id, name, format, type, param) VALUES(?,?,?,?,?)
		 ON CONFLICT(instance_id, name) DO UPDATE SET format=excluded.format, type=excluded.type, param=excluded.param`,
		instanceID, name, format, typ, param)
	return err
}

func (s *Store) ListRepos(instanceID int64) ([]Repo, error) {
	rows, err := s.db.Query(
		`SELECT id, instance_id, name, format, type, param FROM repos WHERE instance_id = ? ORDER BY type, name`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Repo
	for rows.Next() {
		var r Repo
		if err := rows.Scan(&r.ID, &r.InstanceID, &r.Name, &r.Format, &r.Type, &r.Param); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) RepoByID(id int64) (*Repo, error) {
	var r Repo
	err := s.db.QueryRow(
		`SELECT id, instance_id, name, format, type, param FROM repos WHERE id = ?`, id).
		Scan(&r.ID, &r.InstanceID, &r.Name, &r.Format, &r.Type, &r.Param)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) DeleteRepo(instanceID int64, name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM repos WHERE instance_id = ? AND name = ?`, instanceID, name); err != nil {
		return err
	}
	// 清理矩阵中引用该仓库的权限
	var ids []int64
	rows, err := tx.Query(`SELECT id FROM users WHERE instance_id = ?`, instanceID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM permissions WHERE user_id = ? AND repo_name = ?`, id, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---------------- User ----------------

// CreateUser 新建用户；password 可为空（用于从 Nexus 导入已有用户，密码未知不同步）。
func (s *Store) CreateUser(instanceID int64, username, email, password string) (int64, error) {
	var enc string
	if password != "" {
		var err error
		if enc, err = s.crypto.Encrypt(password); err != nil {
			return 0, err
		}
	}
	res, err := s.db.Exec(
		`INSERT INTO users(instance_id, username, email, password_enc, enabled) VALUES(?,?,?,?,1)`,
		instanceID, username, email, enc)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateUser(id int64, email, password *string, enabled *bool) error {
	sets := []string{}
	args := []any{}
	if email != nil {
		sets = append(sets, "email = ?")
		args = append(args, *email)
	}
	if password != nil && *password != "" {
		enc, err := s.crypto.Encrypt(*password)
		if err != nil {
			return err
		}
		sets = append(sets, "password_enc = ?", "password_dirty = 1")
		args = append(args, enc)
	}
	if enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolToInt(*enabled))
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.db.Exec(`UPDATE users SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
	return err
}

func (s *Store) DeleteUser(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM permissions WHERE user_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// ClearUserPasswordDirty 密码已成功推送到 Nexus 后清除待同步标记。
func (s *Store) ClearUserPasswordDirty(id int64) error {
	_, err := s.db.Exec(`UPDATE users SET password_dirty = 0 WHERE id = ?`, id)
	return err
}

func (s *Store) ListUsers(instanceID int64) ([]User, error) {
	rows, err := s.db.Query(
		`SELECT id, instance_id, username, email, password_enc, password_dirty, enabled FROM users WHERE instance_id = ? ORDER BY username`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var enc string
		var en, dirty int
		if err := rows.Scan(&u.ID, &u.InstanceID, &u.Username, &u.Email, &enc, &dirty, &en); err != nil {
			return nil, err
		}
		u.Enabled = en != 0
		u.PasswordDirty = dirty != 0
		if p, err := s.crypto.Decrypt(enc); err == nil {
			u.Password = p
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 加载权限矩阵
	for i := range out {
		perms, err := s.permsForUser(out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Perms = perms
	}
	return out, nil
}

func (s *Store) GetUser(id int64) (*User, error) {
	var u User
	var enc string
	var en, dirty int
	err := s.db.QueryRow(
		`SELECT id, instance_id, username, email, password_enc, password_dirty, enabled FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.InstanceID, &u.Username, &u.Email, &enc, &dirty, &en)
	if err != nil {
		return nil, err
	}
	u.Enabled = en != 0
	u.PasswordDirty = dirty != 0
	if p, err := s.crypto.Decrypt(enc); err == nil {
		u.Password = p
	}
	u.Perms, err = s.permsForUser(u.ID)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) permsForUser(userID int64) (map[string]string, error) {
	rows, err := s.db.Query(`SELECT repo_name, level FROM permissions WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var repo, level string
		if err := rows.Scan(&repo, &level); err != nil {
			return nil, err
		}
		m[repo] = level
	}
	return m, rows.Err()
}

// SetPermission 设置/清除矩阵单元格；level 为空表示清除。
func (s *Store) SetPermission(userID int64, repoName, level string) error {
	if level == "" {
		_, err := s.db.Exec(`DELETE FROM permissions WHERE user_id = ? AND repo_name = ?`, userID, repoName)
		return err
	}
	_, err := s.db.Exec(
		`INSERT INTO permissions(user_id, repo_name, level) VALUES(?,?,?)
		 ON CONFLICT(user_id, repo_name) DO UPDATE SET level=excluded.level`,
		userID, repoName, level)
	return err
}

// ---------------- Settings / Audit ----------------

func (s *Store) GetAnonymousSetting(instanceID int64) bool {
	var en int
	err := s.db.QueryRow(`SELECT anonymous_enabled FROM settings WHERE instance_id = ?`, instanceID).Scan(&en)
	return err == nil && en != 0
}

func (s *Store) SetAnonymousSetting(instanceID int64, enabled bool) error {
	_, err := s.db.Exec(
		`INSERT INTO settings(instance_id, anonymous_enabled) VALUES(?,?)
		 ON CONFLICT(instance_id) DO UPDATE SET anonymous_enabled=excluded.anonymous_enabled`,
		instanceID, boolToInt(enabled))
	return err
}

func (s *Store) AddAudit(action, target, detail, result string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_logs(ts, action, target, detail, result) VALUES(?,?,?,?,?)`,
		time.Now().Format("2006-01-02 15:04:05"), action, target, detail, result)
	return err
}

func (s *Store) ListAudit(limit int) ([]AuditLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, ts, action, target, detail, result FROM audit_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditLog
	for rows.Next() {
		var a AuditLog
		if err := rows.Scan(&a.ID, &a.TS, &a.Action, &a.Target, &a.Detail, &a.Result); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------------- 平台用户 ----------------

// CountPlatformUsers 平台用户总数（用于首启引导判断）。
func (s *Store) CountPlatformUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM platform_users`).Scan(&n)
	return n, err
}

// CreatePlatformUser 创建平台用户。
func (s *Store) CreatePlatformUser(username, passwordHash, email string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO platform_users(username, password_hash, email, enabled, created_at) VALUES(?,?,?,1,?)`,
		username, passwordHash, email, time.Now().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListPlatformUsers() ([]PlatformUser, error) {
	rows, err := s.db.Query(
		`SELECT id, username, password_hash, email, enabled, created_at, last_login_at
		 FROM platform_users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PlatformUser
	for rows.Next() {
		var u PlatformUser
		var en int
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Email, &en, &u.CreatedAt, &u.LastLoginAt); err != nil {
			return nil, err
		}
		u.Enabled = en != 0
		out = append(out, u)
	}
	if out == nil {
		out = []PlatformUser{}
	}
	return out, rows.Err()
}

func (s *Store) GetPlatformUserByUsername(username string) (*PlatformUser, error) {
	var u PlatformUser
	var en int
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, email, enabled, created_at, last_login_at
		 FROM platform_users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Email, &en, &u.CreatedAt, &u.LastLoginAt)
	if err != nil {
		return nil, err
	}
	u.Enabled = en != 0
	return &u, nil
}

func (s *Store) GetPlatformUserByID(id int64) (*PlatformUser, error) {
	var u PlatformUser
	var en int
	err := s.db.QueryRow(
		`SELECT id, username, password_hash, email, enabled, created_at, last_login_at
		 FROM platform_users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Email, &en, &u.CreatedAt, &u.LastLoginAt)
	if err != nil {
		return nil, err
	}
	u.Enabled = en != 0
	return &u, nil
}

// UpdatePlatformUser 更新邮箱/启停（不传的字段保持不变）。
func (s *Store) UpdatePlatformUser(id int64, email *string, enabled *bool) error {
	sets, args := []string{}, []any{}
	if email != nil {
		sets = append(sets, "email = ?")
		args = append(args, *email)
	}
	if enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolToInt(*enabled))
	}
	if len(sets) == 0 {
		return nil
	}
	args = append(args, id)
	_, err := s.db.Exec(`UPDATE platform_users SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
	return err
}

// SetPlatformUserPassword 重设密码（管理员重置或本人修改）。
func (s *Store) SetPlatformUserPassword(id int64, passwordHash string) error {
	_, err := s.db.Exec(`UPDATE platform_users SET password_hash = ? WHERE id = ?`, passwordHash, id)
	return err
}

func (s *Store) DeletePlatformUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM platform_users WHERE id = ?`, id)
	return err
}

func (s *Store) TouchPlatformUserLogin(id int64) error {
	_, err := s.db.Exec(
		`UPDATE platform_users SET last_login_at = ? WHERE id = ?`,
		time.Now().Format("2006-01-02 15:04:05"), id)
	return err
}

// AddLoginLog 记录登录日志（成功/失败都记）。
func (s *Store) AddLoginLog(username, ip, result, detail string) error {
	_, err := s.db.Exec(
		`INSERT INTO login_logs(ts, username, ip, result, detail) VALUES(?,?,?,?,?)`,
		time.Now().Format("2006-01-02 15:04:05"), username, ip, result, detail)
	return err
}

func (s *Store) ListLoginLogs(limit int) ([]LoginLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(
		`SELECT id, ts, username, ip, result, detail FROM login_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoginLog
	for rows.Next() {
		var l LoginLog
		if err := rows.Scan(&l.ID, &l.TS, &l.Username, &l.IP, &l.Result, &l.Detail); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	if out == nil {
		out = []LoginLog{}
	}
	return out, rows.Err()
}

// ---------------- Template ----------------

// UpsertTemplate 新建/更新模板（同名更新），并维护用户绑定。
func (s *Store) UpsertTemplate(instanceID int64, name, matchType, matchValue, level string, userIDs []int64) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var id int64
	err = tx.QueryRow(`SELECT id FROM templates WHERE instance_id = ? AND name = ?`, instanceID, name).Scan(&id)
	if err == sql.ErrNoRows {
		res, err := tx.Exec(
			`INSERT INTO templates(instance_id, name, match_type, match_value, level) VALUES(?,?,?,?,?)`,
			instanceID, name, matchType, matchValue, level)
		if err != nil {
			return 0, err
		}
		id, _ = res.LastInsertId()
	} else if err != nil {
		return 0, err
	} else {
		if _, err := tx.Exec(
			`UPDATE templates SET match_type = ?, match_value = ?, level = ? WHERE id = ?`,
			matchType, matchValue, level, id); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(`DELETE FROM template_users WHERE template_id = ?`, id); err != nil {
			return 0, err
		}
	}
	for _, uid := range userIDs {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO template_users(template_id, user_id) VALUES(?,?)`, id, uid); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Store) ListTemplates(instanceID int64) ([]Template, error) {
	rows, err := s.db.Query(
		`SELECT id, instance_id, name, match_type, match_value, level FROM templates WHERE instance_id = ? ORDER BY id`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Template
	for rows.Next() {
		var t Template
		if err := rows.Scan(&t.ID, &t.InstanceID, &t.Name, &t.MatchType, &t.MatchValue, &t.Level); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		urows, err := s.db.Query(
			`SELECT u.id, u.username FROM template_users tu JOIN users u ON u.id = tu.user_id
			 WHERE tu.template_id = ? ORDER BY u.username`, out[i].ID)
		if err != nil {
			return nil, err
		}
		for urows.Next() {
			var uid int64
			var name string
			if err := urows.Scan(&uid, &name); err != nil {
				urows.Close()
				return nil, err
			}
			out[i].UserIDs = append(out[i].UserIDs, uid)
			out[i].UserNames = append(out[i].UserNames, name)
		}
		urows.Close()
	}
	if out == nil {
		out = []Template{}
	}
	return out, nil
}

func (s *Store) GetTemplate(id int64) (*Template, error) {
	var t Template
	err := s.db.QueryRow(
		`SELECT id, instance_id, name, match_type, match_value, level FROM templates WHERE id = ?`, id).
		Scan(&t.ID, &t.InstanceID, &t.Name, &t.MatchType, &t.MatchValue, &t.Level)
	if err != nil {
		return nil, err
	}
	// 加载绑定的用户（apply 等场景需要）
	rows, err := s.db.Query(
		`SELECT u.id, u.username FROM template_users tu JOIN users u ON u.id = tu.user_id
		 WHERE tu.template_id = ? ORDER BY u.username`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var uid int64
		var name string
		if err := rows.Scan(&uid, &name); err != nil {
			return nil, err
		}
		t.UserIDs = append(t.UserIDs, uid)
		t.UserNames = append(t.UserNames, name)
	}
	return &t, rows.Err()
}

func (s *Store) DeleteTemplate(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM template_users WHERE template_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM templates WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func splitAndTrim(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
