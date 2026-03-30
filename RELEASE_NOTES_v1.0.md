# awd-c0iq v1.0

## Release

- 首个可发布版本 `v1.0`
- Windows 可执行文件：`awd-c0iq-nocgo.exe`
- 推荐通过 GitHub Release 上传 exe 资产，不将运行产物提交到源码仓库

## Included

- SSH 登录、终端会话、SFTP 文件管理
- WebShell 测试、命令执行、Flag 获取
- Undead / MD5 / Worm 载荷维护与上传
- 防守动作、站点/数据库备份恢复、改密
- 实时抓流量、抓包记录搜索、HTTP 明文请求识别与详情预览

## Build

```powershell
$env:CGO_ENABLED='0'
go build -tags production -o dist\awd-c0iq-nocgo.exe .
```

## Notes

- `config.yaml`、`log/`、`output/`、`pcap/` 等运行数据已排除出 Git
- 仓库内提供 `config.example.yaml` 作为示例配置
