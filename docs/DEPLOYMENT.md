# EdgeLink 部署指南

## 安装

将编译好的二进制文件复制到 `/usr/bin/`:

```bash
cp edgelink-controller edgelink-client edgelink-server /usr/bin/
chmod +x /usr/bin/edgelink-*
```

## Controller 部署

### 1. 创建配置目录

```bash
mkdir -p /etc/edgelink
```

### 2. 生成配置文件

```bash
edgelink-controller init --output /etc/edgelink/controller.json
```

然后编辑配置文件，修改以下关键项：
- `jwt.secret`: 修改为随机字符串（至少32字符）
- `builtin_stun.external_ip`: 设置为服务器的公网 IP

### 3. 安装 systemd 服务

```bash
cp systemd/edgelink-controller.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable edgelink-controller
systemctl start edgelink-controller
```

### 4. 手动启动

```bash
edgelink-controller -c /etc/edgelink/controller.json
```

### 5. CLI 管理命令

Controller 运行时，可以使用 CLI 命令管理：

```bash
# 查看状态
edgelink-controller status

# 列出节点
edgelink-controller node list
edgelink-controller node list --online

# 创建 auth key
edgelink-controller authkey create --network 1
edgelink-controller authkey create --network 1 --reusable

# 列出网络
edgelink-controller network list

# 查看延迟矩阵
edgelink-controller latency
```

---

## Client 部署

### 1. 生成配置

```bash
edgelink-client init --output /etc/edgelink/client.json --url ws://YOUR_CONTROLLER:8080
```

或手动创建 `/etc/edgelink/client.json`:

```json
{
    "controller_url": "ws://140.143.162.240:8888",
    "machine_key_pub": "生成的公钥",
    "machine_key_priv": "生成的私钥",
    "auth_key": "",
    "tun_name": "edgelink0",
    "mtu": 1400,
    "log_level": "info"
}
```

生成密钥:
```bash
edgelink-client keygen
```

### 2. 安装 systemd 服务

```bash
cp systemd/edgelink-client.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable edgelink-client
systemctl start edgelink-client
```

### 3. 手动启动

```bash
edgelink-client connect -c /etc/edgelink/client.json
```

---

## 防火墙配置

### Controller

```bash
# HTTP/WebSocket
firewall-cmd --permanent --add-port=8080/tcp

# STUN (如果启用)
firewall-cmd --permanent --add-port=3478/udp

firewall-cmd --reload
```

### Client

```bash
# 允许 TUN 流量
firewall-cmd --permanent --add-interface=edgelink0 --zone=trusted
firewall-cmd --reload
```

---

## 日志

```bash
# Controller 日志
journalctl -u edgelink-controller -f

# Client 日志
journalctl -u edgelink-client -f
```

---

## 故障排查

### Controller 无法启动

1. 检查端口是否被占用:
   ```bash
   ss -tlnp | grep 8080
   ```

2. 检查配置文件语法:
   ```bash
   cat /etc/edgelink/controller.json | python3 -m json.tool
   ```

### CLI 命令报错 "Controller is not running"

确保 Controller 正在运行：
```bash
systemctl status edgelink-controller
```

### Client 无法连接

1. 检查 Controller 是否可达:
   ```bash
   curl http://controller:8080/api/v1/health
   ```

2. 检查密钥是否正确

### STUN 不工作

1. 确认 `external_ip` 已配置为公网 IP
2. 确认 UDP 3478 端口已开放

