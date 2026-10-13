package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"

	"nexus-perm/internal/api"
	"nexus-perm/internal/auth"
	"nexus-perm/internal/store"
)

//go:embed web/index.html
var webFS embed.FS

// 构建信息（CI 通过 -ldflags "-X main.version=... -X main.buildTime=..." 注入）
var (
	version   = "dev"
	buildTime = "unknown"
)

// bootstrapAdmin 首次启动（无任何平台用户）时创建 admin 账号。
// 密码来源：环境变量 NEXUS_PERM_ADMIN_PASSWORD，否则随机生成并落盘到
// data/INITIAL_ADMIN_PASSWORD.txt（权限 0600），请登录后立即修改。
func bootstrapAdmin(st *store.Store, dataDir string) error {
	n, err := st.CountPlatformUsers()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}

	password := os.Getenv("NEXUS_PERM_ADMIN_PASSWORD")
	fromEnv := password != ""
	if !fromEnv {
		password = auth.RandomPassword(16)
	}
	authSvc, err := auth.New(dataDir)
	if err != nil {
		return err
	}
	hash, err := authSvc.HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := st.CreatePlatformUser("admin", hash, "admin@localhost"); err != nil {
		return err
	}

	log.Println("========================================================")
	log.Println(" 首次启动：已创建平台管理员账号")
	log.Println("   用户名: admin")
	if fromEnv {
		log.Println("   密码  : （来自环境变量 NEXUS_PERM_ADMIN_PASSWORD）")
	} else {
		p := filepath.Join(dataDir, "INITIAL_ADMIN_PASSWORD.txt")
		content := "nexus-perm 初始管理员密码（请登录后立即修改）\n\n用户名: admin\n密码: " + password + "\n"
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			return err
		}
		log.Printf("   密码  : %s", password)
		log.Printf("   （已同时写入 %s，权限 0600）", p)
	}
	log.Println("========================================================")
	return nil
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "监听地址（如 0.0.0.0:8080 允许远程访问）")
	dataDir := flag.String("data", "./data", "数据目录（SQLite + 密钥）")
	showVersion := flag.Bool("version", false, "打印版本号后退出")
	flag.Parse()

	if *showVersion {
		fmt.Printf("nexus-perm %s (built %s)\n", version, buildTime)
		return
	}

	st, err := store.Open(*dataDir)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()

	authSvc, err := auth.New(*dataDir)
	if err != nil {
		log.Fatalf("初始化认证服务失败: %v", err)
	}
	if err := bootstrapAdmin(st, *dataDir); err != nil {
		log.Fatalf("创建初始管理员失败: %v", err)
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	srv := api.NewServer(st, authSvc)
	srv.Register(r)

	// 前端 SPA（内嵌在二进制中）
	r.GET("/", func(c *gin.Context) {
		data, err := webFS.ReadFile("web/index.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "前端资源缺失")
			return
		}
		// 禁用缓存：避免浏览器标签页停留在旧版 UI
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	})

	log.Printf("Nexus 权限管理平台已启动: http://%s (version %s, built %s)", *addr, version, buildTime)
	log.Printf("数据目录: %s", *dataDir)
	if err := r.Run(*addr); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}
