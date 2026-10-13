package nexus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client 封装 Nexus Repository Manager 3 REST API（/service/rest/v1）。
type Client struct {
	baseURL string
	user    string
	pass    string
	http    *http.Client
}

func NewClient(baseURL, user, pass string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		user:    user,
		pass:    pass,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// NXRepo Nexus 侧的仓库对象（仅取用得到的字段）。
type NXRepo struct {
	Name   string `json:"name"`
	Format string `json:"format"`
	Type   string `json:"type"`
}

type NXUser struct {
	UserID        string   `json:"userId"`
	FirstName     string   `json:"firstName"`
	LastName      string   `json:"lastName"`
	EmailAddress  string   `json:"emailAddress"`
	Status        string   `json:"status"`
	Roles         []string `json:"roles"`
	Source        string   `json:"source"`
	ExternalRoles []string `json:"externalRoles"`
}

type NXRole struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Privileges  []string `json:"privileges"`
	Roles       []string `json:"roles"`
	Source      string   `json:"source"` // default = 内置角色
}

func (c *Client) do(method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.SetBasicAuth(c.user, c.pass)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}

// Check 测活：GET /service/rest/v1/status
func (c *Client) Check() (map[string]any, error) {
	code, data, err := c.do("GET", "/service/rest/v1/status", nil)
	if err != nil {
		return nil, fmt.Errorf("连接失败: %w", err)
	}
	if code != 200 {
		return nil, fmt.Errorf("HTTP %d（请检查地址与 admin 凭据）", code)
	}
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out, nil
}

// ---------------- 仓库 ----------------

func (c *Client) ListRepositories() ([]NXRepo, error) {
	code, data, err := c.do("GET", "/service/rest/v1/repositories", nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("列出仓库失败 HTTP %d", code)
	}
	var out []NXRepo
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetRepository 读取单个仓库（Nexus 3.49 仅返回摘要：name/format/type/url，
// group 成员等配置字段不返回，故无法用于成员校验）。
func (c *Client) GetRepository(name string) (NXRepo, error) {
	code, data, err := c.do("GET", "/service/rest/v1/repositories/"+name, nil)
	if err != nil {
		return NXRepo{}, err
	}
	if code != 200 {
		return NXRepo{}, fmt.Errorf("HTTP %d", code)
	}
	var out NXRepo
	if err := json.Unmarshal(data, &out); err != nil {
		return NXRepo{}, err
	}
	return out, nil
}

// ---------------- 用户 ----------------

func (c *Client) ListUsers() ([]NXUser, error) {
	code, data, err := c.do("GET", "/service/rest/v1/security/users", nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("列出用户失败 HTTP %d", code)
	}
	var out []NXUser
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) CreateUser(u NXUser, password string) error {
	payload := map[string]any{
		"userId":       u.UserID,
		"firstName":    firstNonEmpty(u.FirstName, u.UserID),
		"lastName":     firstNonEmpty(u.LastName, "User"), // REST API 不允许 lastName 为空
		"emailAddress": u.EmailAddress,
		"password":     password,
		"status":       firstNonEmpty(u.Status, "active"), // active / disabled
		"roles":        u.Roles,
	}
	code, data, err := c.do("POST", "/service/rest/v1/security/users", payload)
	if err != nil {
		return err
	}
	if code != 200 && code != 201 {
		return fmt.Errorf("HTTP %d: %s", code, string(data))
	}
	return nil
}

// UpdateUser 用列表端点拿到的完整对象修改 roles 后 PUT（Nexus 不支持 GET /users/{id}，返回 405）。
func (c *Client) UpdateUser(u NXUser) error {
	payload := map[string]any{
		"userId":        u.UserID,
		"firstName":     firstNonEmpty(u.FirstName, u.UserID),
		"lastName":      firstNonEmpty(u.LastName, "User"),
		"emailAddress":  u.EmailAddress,
		"status":        firstNonEmpty(u.Status, "active"),
		"roles":         u.Roles,
		"source":        firstNonEmpty(u.Source, "default"),
		"externalRoles": u.ExternalRoles,
	}
	code, data, err := c.do("PUT", "/service/rest/v1/security/users/"+u.UserID, payload)
	if err != nil {
		return err
	}
	if code != 200 && code != 204 {
		return fmt.Errorf("HTTP %d: %s", code, string(data))
	}
	return nil
}

func (c *Client) DeleteUser(userID string) error {
	code, _, err := c.do("DELETE", "/service/rest/v1/security/users/"+userID, nil)
	if err != nil {
		return err
	}
	if code != 200 && code != 204 {
		return fmt.Errorf("HTTP %d", code)
	}
	return nil
}

// ---------------- 角色 ----------------

func (c *Client) ListRoles() ([]NXRole, error) {
	code, data, err := c.do("GET", "/service/rest/v1/security/roles", nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("列出角色失败 HTTP %d", code)
	}
	var out []NXRole
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PutRole 创建/更新角色，一律提交完整权限列表。
// 注意：GET /security/roles/{id} 返回的 privileges 可能不完整，
// 绝不能用"GET+合并"的方式，否则会把已有权限覆盖丢失。
func (c *Client) PutRole(r NXRole) error {
	payload := map[string]any{
		"id":          r.ID,
		"name":        firstNonEmpty(r.Name, r.ID),
		"description": r.Description,
		"privileges":  r.Privileges,
		"roles":       []string{},
	}
	code, data, err := c.do("POST", "/service/rest/v1/security/roles", payload)
	if err != nil {
		return err
	}
	if code == 200 || code == 201 {
		return nil
	}
	// 已存在 -> PUT 完整列表
	code, data, err = c.do("PUT", "/service/rest/v1/security/roles/"+r.ID, payload)
	if err != nil {
		return err
	}
	if code != 200 && code != 204 {
		return fmt.Errorf("HTTP %d: %s", code, string(data))
	}
	return nil
}

func (c *Client) DeleteRole(id string) error {
	code, _, err := c.do("DELETE", "/service/rest/v1/security/roles/"+id, nil)
	if err != nil {
		return err
	}
	if code != 200 && code != 204 {
		return fmt.Errorf("HTTP %d", code)
	}
	return nil
}

// ---------------- 匿名访问 ----------------

func (c *Client) SetAnonymous(enabled bool) error {
	payload := map[string]any{
		"enabled":    enabled,
		"userId":     "anonymous",
		"realmName":  "NexusAuthorizingRealm",
	}
	code, _, err := c.do("PUT", "/service/rest/v1/security/anonymous", payload)
	if err != nil {
		return err
	}
	if code != 200 && code != 204 {
		return fmt.Errorf("HTTP %d", code)
	}
	return nil
}

// GetAnonymous 读取匿名访问开关。
// 注意：不能从 GET /security/users 里 anonymous 用户的 status 推断——
// 实测匿名关闭时该用户仍以 active 出现在列表中。
func (c *Client) GetAnonymous() (bool, error) {
	code, data, err := c.do("GET", "/service/rest/v1/security/anonymous", nil)
	if err != nil {
		return false, err
	}
	if code != 200 {
		return false, fmt.Errorf("HTTP %d", code)
	}
	var out struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return false, err
	}
	return out.Enabled, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
