./traffic-client -server http://服务器ip:18080 -client-id web1 -device ens18 -bpf "tcp port 80" -duration 60 -interval 30

客户端支持的参数：
-server：服务端地址
默认 http://127.0.0.1:8080
示例：http://你的服务器IP:8080
-client-id：客户端标识（比如 web1、db1），用于文件名和服务端日志识别。
-device：网卡名称（留空 = 所有网卡）
可以先不写，直接跑一次看日志里枚举的设备名，再指定。
-bpf：BPF 过滤表达式（可空）
例如："tcp port 80"、"port 80 or port 443"。
-duration：每轮抓包时长（秒），默认 60
-interval：轮与轮之间间隔（秒）
> 0：循环执行
= 0：只抓一次就退出