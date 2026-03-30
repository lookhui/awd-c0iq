# awd-c0iq

`awd-c0iq` 是一个面向 AWD / CTF 靶场值守、排障、批量操作和流量分析的桌面工具，当前项目使用 Go + Wails 构建。

## 构建

推荐构建命令：

```powershell
$env:CGO_ENABLED='0'
go build -tags production -o dist\awd-c0iq-nocgo.exe .
```

普通构建命令：

```powershell
go build -tags production -o dist\awd-c0iq.exe .
```
<img width="1920" height="1016" alt="image" src="https://github.com/user-attachments/assets/5a7a6567-0471-4d6d-b005-a4771e7a7ffb" />

## 主要功能

- SSH 登录、终端会话、远程文件管理
- WebShell 测试、命令执行、Flag 获取
- Undead / MD5 / Worm 载荷维护
- 网站与数据库备份、恢复、加固
- 远程抓流量、抓包记录检索、HTTP 明文预览

## 文档

- [USAGE.md](./USAGE.md)
- [使用说明.md](./使用说明.md)
- [RELEASE_NOTES_v1.0.md](./RELEASE_NOTES_v1.0.md)

## 发布建议

- 源代码仓库只保留构建所需源码、配置示例和文档
- `exe`、`zip` 等发布包上传到 GitHub Releases
- 版本通过 tag 管理，例如 `v1.0`
