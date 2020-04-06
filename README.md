# sandwich

sandwich 是一个傻瓜化、实现简单、伪装强、安全的梯子。使用 HTTPS 进行通信，伪装为普通网站请求。使用 IP 段、而不是规则表进行智能代理。

# 本地代理

由于 sandwich 本地代理使用了 macOS 专用的命令，所以本地代理仅支持 macOS。

```bash
./sandwich -listen-addr=:1186 \
 -remote-proxy-addr=https://<youdomain.com>:443 \
 -secret-key=dcf10cfe73d1bf97f7b3
```

# 海外代理

需要 CA 证书、秘钥文件。推荐使用 [acme.sh](https://github.com/acmesh-official/acme.sh) 申请 Let's Encrypt 证书。sandwich 服务端代理使用了 daemon，所以仅支持 *nix 系统，windows 不支持。

```bash
./sandwich-amd64-linux -cert-file=/root/.acme.sh/<youdomain.com>/fullchain.cer  \ 
 -private-key-file=/root/.acme.sh/<youdomain.com>/<youdomain.com>.key \
 -listen-addr=:443 \
 -remote-proxy-mode=true \
 -secret-key=dcf10cfe73d1bf97f7b3
```

仅需两步，什么也不做，什么也不要，就这么简单！

# 简单说明

如果用浏览器访问 https://<youdomain.com>，出现的就是一个正常普通的反向代理网站，这就是伪装强的原因。反向代理的网站默认为 [http//mirrors.codec-cluster.org/](http//mirrors.codec-cluster.org/) ，可在海外的 sandwich 上用 `-reversed-website` 参数指定。

所有支持系统代理的应用程序，比如 Slack，Chrome，Safari 之类的 HTTP/HTTPS 请求，都会发到 sandwich local proxy 来决定是否需要海外的 sandwich 代理。

如果你用的程序不支持系统代理，但支持手动设置，那就手动设置 HTTP/HTTPS 代理。对于两者都不支持的应用程序，比如  ssh 命令行程序，可使用 Proxifier 来强制它走代理。

# 懒，自行编译

已编译好的二进制文件？我懒，自行编译吧。:)

# 相关博客

* [仅需 120 行 Go 代码实现双重 HTTP(S) 代理做梯子](https://fanpei91.com/posts/implement-double-proxies-to-cross-firewall-by-using-https/)

* [sandwich: 如何更快、更智能、更傻瓜地看更大的世界？](http://fanpei91.com/posts/smart-proxy-without-rules/)

