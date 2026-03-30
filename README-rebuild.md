# awd-c0iq Rebuild

## 主要入口

- `main.go`：程序入口与 Wails 应用启动
- `internal/bootstrap`：容器、服务装配、启动流程
- `internal/app/bindings`：Wails 绑定层
- `internal/controller`：控制层
- `internal/core/logic`：攻击、防守、检测、Flag、监控、改密逻辑
- `internal/pcapstore` / `internal/pcapsearch` / `internal/pcapserver`：PCAP 入库、索引、上传服务
- `assets/index.html`：静态控制台前端
- `frontend/bindings`：自动生成的 Wails 前端绑定

## 已还原的核心功能

- 目标存活探测与 `output/target.txt` 保存
- WebShell 测试、Undead/MD5/Worm 马上传与命令执行
- Flag 抓取
- SSH 批量改密
- 站点/数据库备份与恢复
- 查壳、站点加固、上传目录只读、简易 WAF
- PCAP 上传、解析、SQLite 存储、Bleve 检索
- 输出文件与日志查看

## 构建

纯 Go 构建：

```powershell
$env:CGO_ENABLED='0'
go build -tags production -o dist\awd-c0iq-nocgo.exe .
```

普通构建：

```powershell
go build -tags production -o dist\awd-c0iq.exe .
```

## 当前产物

- `dist/awd-c0iq.exe`
- `dist/awd-c0iq-nocgo.exe`
