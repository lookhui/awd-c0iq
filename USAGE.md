# awd-c0iq 使用指南

## 一、打包方法

### 1. 免 CGO 打包

推荐发布方式：

```powershell
$env:CGO_ENABLED='0'
go build -tags production -o dist\awd-c0iq-nocgo.exe .
```

### 2. 普通打包

```powershell
go build -tags production -o dist\awd-c0iq.exe .
```

### 3. 推荐发布内容

建议上传到 GitHub Release 的附件：

- `awd-c0iq-v1.0-windows-amd64.zip`
- `RELEASE_NOTES_v1.0.md`

建议保留在源代码仓库中的文档：

- `README.md`
- `USAGE.md`
- `使用说明.md`
- `config.example.yaml`

## 二、运行前准备

### 1. 本机环境

- Windows 环境，直接运行 `exe`
- 如需本地联调，可使用 WSL
- 如需自行编译，确保本机已安装 Go

### 2. 目标环境

- 一台可通过 SSH 登录的靶机
- 靶机 IP、SSH 端口、用户名、密码
- 一个可用的 WebShell
- 如需抓流量，远端需要安装 `tcpdump`
- 如需文件管理，SSH 账号需要对目标目录有读写权限

### 3. WebShell 关键信息

- Shell 地址，例如 `/shell.php`
- 请求方式：`GET` 或 `POST`
- 参数名，例如 `pass`、`b`
- 固定查询参数，例如 `a=system`
- 载荷类型是“PHP 代码”还是“原始命令”

## 三、建议使用顺序

### 1. 先建立 SSH 连接

程序启动后先在登录窗口填写：

- IP 地址
- 端口，默认 `22`
- 用户名，默认 `root`
- 密码

连接成功后：

- 顶部状态栏会显示当前 SSH 会话
- 总览页会进入 SSH 终端和文件管理器
- 防守和流量模块会复用这条 SSH 会话

### 2. 再配置资产模块

资产模块负责维护：

- 目标列表
- WebShell 调用方式
- 参数名
- 固定查询参数
- 远程工作目录

常见场景：

#### 场景 A：一句话木马

- 方法：`POST`
- 参数名：`pass`
- 固定查询：留空
- 载荷类型：PHP 代码

#### 场景 B：命令执行型 Shell

请求形式：

```text
http://127.0.0.1:9001/shell.php?a=system
POST: b=whoami
```

应这样配置：

- 方法：`POST`
- 参数名：`b`
- 固定查询：`a=system`
- 载荷类型：原始命令

### 3. 最后再跑攻击链

建议按这个顺序：

1. `Shell 测试`
2. `命令执行`
3. `Flag 获取`
4. `载荷攻防`

## 四、模块说明

### 1. 总览模块

#### SSH 终端会话

可用于：

- 执行远程命令
- 查看权限、目录、系统环境
- 排查站点和进程问题

建议先执行：

```bash
whoami
pwd
uname -a
ls -la
```

#### 文件管理器

支持：

- 浏览目录
- 进入上级目录
- 刷新
- 上传
- 下载
- 删除
- 重命名
- 编辑文本文件

### 2. 资产模块

用于维护基础配置，不直接执行攻击。

主要配置项：

- 目标列表
- WebShell 请求方式
- 参数名
- 固定查询参数
- 远程工作目录

### 3. 攻击模块

#### Shell 测试

输出文件：

- `output/success.txt`
- `output/error.txt`

这两个文件现在都是追加写入，不会覆盖旧记录。

#### 命令执行

用于直接下发命令并查看回显。

#### Flag 获取

结果写入：

- `output/flag.txt`

`flag.txt` 已改为追加模式，每条记录单独占一行。

#### 载荷攻防

可直接在界面中维护：

- Undead
- MD5
- Worm

### 4. 防守模块

默认只对当前 SSH 主机执行。

常用动作：

- 网站备份
- 数据库备份
- 查杀恶意文件
- 恢复站点
- 站点加固

### 5. 流量模块

当前通过 SSH 在远端启动 `tcpdump`。

支持：

- 实时抓流量
- 停止抓包
- 查看抓包记录
- 搜索历史记录
- 自动识别常见协议
- 查看 HTTP 明文请求详情

当前会自动识别：

- HTTP
- HTTPS
- SSH
- DNS
- MySQL
- Redis
- TCP
- UDP

搜索框支持 `&` 联合查询，例如：

```text
80&post&172.27.132.236
```

## 五、输出文件和日志

常用位置：

- `output/flag.txt`
- `output/error.txt`
- `output/success.txt`
- `log/`
- `pcap/`

HTTP 报错日志已增强，包含：

- URL
- Method
- POST Body
- Status Code
- Error

## 六、常见排障顺序

1. 先看顶部 SSH 状态是否正常
2. 在 SSH 终端执行 `whoami`、`pwd`、`ls`
3. 在资产模块检查 WebShell 方法、参数名、固定查询
4. 在攻击模块先跑 `Shell 测试`
5. 再执行 `id` 或 `whoami`
6. 流量模块没数据时，先确认远端有 `tcpdump`
7. 最后查看 `output/error.txt` 和 `log/`

## 七、GitHub Release 建议

推荐流程：

1. 只把源码、配置示例和文档放到仓库
2. 不把 zip、exe 这类发布包提交到主仓库
3. 通过 `v1.0` tag 创建 GitHub Release
4. 把 `awd-c0iq-v1.0-windows-amd64.zip` 上传为 Release 附件

GitHub Release 会自动附带：

- Source code (zip)
- Source code (tar.gz)

## 八、注意事项

- 仅在已授权的 AWD / CTF / 靶场环境中使用
- WebShell 参数、方法、固定查询必须匹配
- 流量模块依赖远端 `tcpdump`
- HTTPS 不能直接查看明文请求体
- 发布给队友时，优先发 GitHub Release 附件
