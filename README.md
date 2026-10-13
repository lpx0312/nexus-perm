# nexus-perm -- Nexus 权限管理平台

Nexus Repository Manager 3 的仓库级权限可视化管理工具（前后端一体，单二进制部署）。
把 `01-permission-management/scripts/nexus-permission-setup.sh` 的"改脚本 -> 跑脚本"模式升级为 Web 可视化管理。

**定位：只管权限，不管仓库。** 仓库清单从 Nexus 只读同步，本工具不创建/修改/删除任何 Nexus 仓库。
**平台自身有账号体系**：打开页面必须登录，可在"用户管理"页维护平台账号（不做权限分级，登录即可用全部功能）。

## 安装与启动

### 方式一：二进制（推荐）

从 [Releases](https://github.com/lpx0312/nexus-perm/releases/latest) 下载对应平台的压缩包：

| 平台 | 文件 |
|---|---|
| Linux x64 | `nexus-perm-linux-amd64.tar.gz` |
| Linux ARM64 | `nexus-perm-linux-arm64.tar.gz` |
| macOS Intel | `nexus-perm-darwin-amd64.tar.gz` |
| macOS Apple Silicon | `nexus-perm-darwin-arm64.tar.gz` |
| Windows x64 | `nexus-perm-windows-amd64.zip` |

```bash
# Linux / macOS 示例
curl -LO https://github.com/lpx0312/nexus-perm/releases/latest/download/nexus-perm-linux-amd64.tar.gz
tar -xzf nexus-perm-linux-amd64.tar.gz
chmod +x nexus-perm-linux-amd64
./nexus-perm-linux-amd64 -addr 0.0.0.0:8080 -data ./data
```

```powershell
# Windows：解压 zip，重命名后运行
ren nexus-perm-windows-amd64.exe nexus-perm.exe
.\nexus-perm.exe -addr 0.0.0.0:8080 -data .\data
```

启动参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-addr` | `127.0.0.1:8080` | 监听地址；远程访问改 `0.0.0.0:8080`（建议配反向代理 + HTTPS） |
| `-data` | `./data` | 数据目录（SQLite + 密钥，需持久化） |
| `-version` | - | 打印版本号后退出 |

systemd 守护（Linux）：

```ini
# /etc/systemd/system/nexus-perm.service
[Unit]
Description=Nexus Permission Manager
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nexus-perm -addr 0.0.0.0:8080 -data /var/lib/nexus-perm
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo install -m 0755 nexus-perm-linux-amd64 /usr/local/bin/nexus-perm
sudo mkdir -p /var/lib/nexus-perm
sudo systemctl daemon-reload && sudo systemctl enable --now nexus-perm
```

### 方式二：Docker

镜像发布在 GHCR：`ghcr.io/lpx0312/nexus-perm`（linux/amd64 + arm64 多架构）。

```bash
docker run -d \
  --name nexus-perm \
  -p 8080:8080 \
  -v nexus-perm-data:/data \
  ghcr.io/lpx0312/nexus-perm:latest

# 查看启动日志（首次启动含管理员随机密码）
docker logs nexus-perm
```

docker-compose：

```yaml
services:
  nexus-perm:
    image: ghcr.io/lpx0312/nexus-perm:latest
    container_name: nexus-perm
    ports:
      - "8080:8080"
    volumes:
      - nexus-perm-data:/data
    restart: unless-stopped

volumes:
  nexus-perm-data:
```

### 方式三：源码编译

```bash
go build -o nexus-perm .      # Go 1.26+，纯 Go 无 CGO
./nexus-perm
```

## 首次登录

启动后自动创建管理员账号 `admin`：
- 密码来自环境变量 `NEXUS_PERM_ADMIN_PASSWORD`；未设置则随机生成，
  打印在启动日志并写入 `data/INITIAL_ADMIN_PASSWORD.txt`（权限 0600），请登录后立即修改

浏览器打开 http://127.0.0.1:8080（或 `http://<服务器IP>:8080`）登录。

## 使用流程

1. **实例**：添加 Nexus 地址 + admin 账号（凭据 AES-GCM 加密存于数据目录 `secret.key`，请妥善保管）；添加后自动同步仓库清单、导入用户
2. **仓库**：只读清单（从 Nexus 刷新）；Nexus 上新增/删除仓库后点一下刷新即可
3. **用户**：添加 Nexus 用户（密码本地加密保存）；或从 Nexus 导入已有用户（密码"未知"，仅管理角色绑定）。**改密码/角色/权限都只存本地，需到"同步下发"推送到 Nexus 才生效**——Nexus 的用户更新接口不接受密码字段（实测 PUT 静默忽略），密码变更通过"删除重建"方式推送，角色权限不受影响
4. **权限管理**：左侧选用户，右侧维护该用户的仓库权限——纵向列表 + 名称/格式/类型/级别筛选 + 勾选批量授权 + 从其他用户复制，仓库再多也不用横向拖
5. **权限模板**：按 前缀/格式/显式列表 匹配仓库，一次定义、套用到多个用户（新成员入职：建用户 -> 套团队模板 -> 同步下发，三步完成）
6. **同步下发**：先"预览差异"看清每个仓库的级别怎么变（Nexus 当前 -> 本地目标），确认后点"推送到 Nexus"；幂等可重复执行
7. **用户管理**：平台账号 CRUD（创建/停用/重置密码/删除）+ 登录日志

## 登录与安全

- JWT（HS256）鉴权，默认有效期 24 小时，"记住登录状态"7 天；密钥存 `data/jwt.key`（重启不失效），也可用环境变量 `NEXUS_PERM_JWT_SECRET` 指定
- 除登录接口外，所有 API 均需登录；用户被停用后已签发的 token 立即失效
- 密码 bcrypt 哈希；强密码策略：至少 8 位且包含大小写字母、数字、特殊字符
- 防爆破：同一用户名连续失败 5 次锁定 15 分钟（内存计数，重启清零）
- 登录日志记录全部成功/失败（含来源 IP），可在"用户管理"页查看
- 自我保护：不能停用/删除自己的账号，不能删除最后一个可用账号

## 目录结构

```
main.go                  入口（embed 前端 + gin + 首启引导 admin）
internal/store/          SQLite 模型与 CRUD + 凭据加密（含平台用户、登录日志）
internal/nexus/          Nexus REST 客户端 + 权限名展开器
internal/auth/           JWT 签发/校验 + bcrypt + 强密码策略
internal/sync/           diff 计算 + apply 引擎（幂等）
internal/api/            gin handlers（含认证中间件、登录防爆破）
web/index.html           零构建 SPA（登录页 + 用户中心权限管理 + 模板）
data/                    运行时生成：nexus-perm.db + secret.key + jwt.key
```

## 页面说明

| 页签 | 作用 |
|---|---|
| 实例 | 多 Nexus 实例管理，凭据加密，一键测活 |
| 仓库 | **只读**：Nexus 仓库清单缓存，一键刷新 |
| 用户 | Nexus 用户账号 CRUD、改密码、启停、从 Nexus 导入 |
| 权限管理 | **核心**：双栏编辑器。左栏选用户，右栏筛选/批量/复制维护仓库权限 |
| 权限模板 | 按前缀/格式/显式列表批量授权，解决仓库量大时的维护效率 |
| 同步下发 | diff 预览（逐仓库级别变化）+ 推送（幂等），匿名访问开关 |
| 用户管理 | **平台自身账号** CRUD + 登录日志（入口：右上角用户菜单） |
| 审计日志 | 实例/仓库/用户/模板/矩阵/apply 全操作留痕 |

## 权限级别（Nexus 3.49 实测结论）

| 级别 | Nexus 权限 | 说明 |
|---|---|---|
| ro | read + browse | 只读：可见、可下载，不能上传/删除 |
| upload | read + browse + edit + add | 只读+上传：覆盖 mvn deploy / npm publish / curl PUT / UI Upload 四条通道，删除一律 403 |
| full | read + browse + edit + add + delete | 读写+删除 |

每个用户自动生成角色 `user-<用户名>`，并自动附加全局权限 `nx-search-read`（搜索）和 `nx-component-upload`（3.49 前端 Upload 菜单开关）。

## 固化在代码里的实测经验

- 角色更新一律 PUT 完整权限列表（GET 角色返回的 privileges 不完整，不能合并）
- 用户查询走列表端点过滤（GET /security/users/{id} 返回 405）
- 权限名格式映射 maven -> maven2
- HTTP PUT 上传校验 edit 而非 add（仅 add 会被 403）
- 访问 group 需要其所有成员仓库都有 read 权限，矩阵页/同步页会给出警告
- 匿名访问状态从 /security/anonymous 读取（用户列表里 anonymous 恒为 active，不可用作判断）
- 用户创建 lastName 置 "User"（REST API 不允许为空）

## CI/CD（GitHub Actions）

仓库内置两个工作流（`.github/workflows/`）：

| 工作流 | 触发条件 | 产物 |
|---|---|---|
| `docker.yml` | push 到 main / 推送 `v*` 标签 / 手动 | 多架构镜像推 GHCR：`ghcr.io/lpx0312/nexus-perm:latest` 与 `:<版本号>`（linux/amd64 + arm64） |
| `release.yml` | 推送 `v*` 标签 / 手动 | 6 平台二进制 + sha256 校验和发布到 GitHub Releases（标签推送发版本号 Release，手动触发覆盖滚动 Release「latest」） |

```bash
# 手动触发（也可在 GitHub Actions 页面点 Run workflow）
gh workflow run docker   --repo lpx0312/nexus-perm
gh workflow run release  --repo lpx0312/nexus-perm

# 跟踪执行
gh run watch --repo lpx0312/nexus-perm
```

发版示例：

```bash
git tag v1.0.0 && git push origin v1.0.0   # 自动构建镜像 + 版本 Release
```

## 安全提示

- 默认监听 127.0.0.1；远程访问请自行加反向代理 + HTTPS
- `data/secret.key` 是 Nexus 凭据解密密钥，`data/jwt.key` 是登录 token 签名密钥，泄露分别等同于泄露全部 Nexus 密码 / 可伪造任意登录态，请妥善保管并定期备份
- "推送并清理"会真实删除 Nexus 上多余的用户/角色，谨慎勾选
- 首次启动的随机 admin 密码请登录后立即修改
