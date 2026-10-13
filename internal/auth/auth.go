package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Claims JWT 声明（平台用户不分角色，登录即可用全部功能）。
type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Service 认证服务：JWT 签发/校验 + bcrypt 密码哈希。
type Service struct {
	secret []byte
}

// New 创建认证服务。密钥优先级：环境变量 NEXUS_PERM_JWT_SECRET > 数据目录 jwt.key（首次随机生成）。
func New(dataDir string) (*Service, error) {
	if env := os.Getenv("NEXUS_PERM_JWT_SECRET"); env != "" {
		return &Service{secret: []byte(env)}, nil
	}
	p := filepath.Join(dataDir, "jwt.key")
	if b, err := os.ReadFile(p); err == nil && len(b) >= 32 {
		return &Service{secret: b}, nil
	}
	// 随机生成并持久化，避免重启后已签发的 token 全部失效
	key := make([]byte, 32)
	if _, err := randRead(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, key, 0o600); err != nil {
		return nil, err
	}
	return &Service{secret: key}, nil
}

const issuer = "nexus-perm"

// GenerateToken 签发 JWT；rememberMe 时延长有效期。
func (s *Service) GenerateToken(userID int64, username string, rememberMe bool) (string, time.Time, error) {
	expiry := 24 * time.Hour
	if rememberMe {
		expiry = 7 * 24 * time.Hour
	}
	expiresAt := time.Now().Add(expiry)
	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    issuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("生成 Token 失败: %w", err)
	}
	return signed, expiresAt, nil
}

// ValidateToken 校验并解析 JWT。
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("不支持的签名方法: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, errors.New("Token 无效或已过期")
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("Token 解析失败")
	}
	return claims, nil
}

// HashPassword bcrypt 加密密码。
func (s *Service) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("密码加密失败: %w", err)
	}
	return string(hash), nil
}

// CheckPassword 校验密码。
func (s *Service) CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ValidateStrongPassword 强密码策略（与 docker-image-sync-platform 一致）：
// 至少 8 位，且包含大写、小写、数字、特殊字符。
func ValidateStrongPassword(password string) error {
	if len(password) < 8 {
		return errors.New("密码长度至少 8 位")
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= '0' && ch <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if !hasUpper {
		return errors.New("密码必须包含至少一个大写字母")
	}
	if !hasLower {
		return errors.New("密码必须包含至少一个小写字母")
	}
	if !hasDigit {
		return errors.New("密码必须包含至少一个数字")
	}
	if !hasSpecial {
		return errors.New("密码必须包含至少一个特殊字符")
	}
	return nil
}
