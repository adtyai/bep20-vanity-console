# BEP20 自用靓号台

本机回环服务。进程只监听 `127.0.0.1:3920`，不要改成 `0.0.0.0`，也不要用 `docker run -p` 发布端口。容器回环和宿主机回环不是同一张网卡，端口映射连不进去。

Linux 生产用宿主机网络。Windows Docker Desktop 的 host 网络和 Linux 不一样，不要拿它当生产部署。

## 启动

在服务器上，目录自定。第一次启动必须给出至少 16 个字符的 `SETUP_TOKEN`。管理员建好之后，这个口令可以留空。不要把真实口令写进仓库。

```bash
mkdir -p /opt/bep20-vanity-console/data
cd /opt/bep20-vanity-console
printf 'SETUP_TOKEN=%s\n' '换成至少16个字符的口令' > .env
docker compose pull
docker compose up -d
docker compose ps
```

容器启动时如果是 root，会把数据目录交给 vanity（uid 65532），然后立刻降权。按上面的命令启动即可，不用再 chown。不要在 compose 里把 `user` 改成别的账号，除非这个目录已经属于那个账号并且可以写入。

浏览器不要直接访问公网地址。在自己的电脑上开隧道：

```bash
ssh -L 3920:127.0.0.1:3920 root@服务器
```

然后打开 `http://127.0.0.1:3920`。第一次用 `SETUP_TOKEN` 建管理员。之后只需要登录密码。

## 停止

用 `docker compose stop` 或 `docker stop -t 30`。直接 `docker stop` 默认只等 10 秒，卡住时可能被强制结束。不要用 `docker kill`。强制结束会丢掉还没写入数据库的命中；已经落到待写文件的，下次启动会导入。
