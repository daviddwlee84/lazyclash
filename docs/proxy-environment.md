# Shell、SSH tunnel 與 Docker 代理

Controller 是管理 API；data proxy 才承載 HTTP／SOCKS 請求。`proxy` 指令使用 target
的 `probe_proxy`，本機亦可讀取核心實際 listener；不猜測某個開放端口就是代理。

## 目前 shell 與單次命令

```sh
eval "$(lazyclash proxy shell-init zsh)"  # bash 亦可
proxy-on desktop
proxy-status
proxy-test
proxy-on server
proxy-off

lazyclash --target desktop proxy env --shell zsh
lazyclash --target server proxy exec -- curl https://example.com/
```

Shell initializer 不在載入時連線。它提供 `lazyclash-proxy-*` functions；沒有同名
functions 時才提供短名稱 `proxy-*`，`--replace` 則明確交由 lazyclash 管理短名稱。
chezmoi adapter 使用這個入口，managed rc 仍由 chezmoi 寫入。

第一次 `proxy-on` 保存原先值及 unset 狀態；切換 target 保留原始快照，`proxy-off`
還原。`NO_PROXY/no_proxy` 預設保留。這表示某些請求仍可能符合使用者原先的 bypass；
環境變數也無法強迫每個程式使用代理。

選擇順序為明確 target／endpoint、明確 `LOCAL_PROXY_URL` override，再考慮本機 target。
多個本機候選提供 picker；JSON／非互動模式回報歧義。失敗不切到另一個代理或 direct。
`withproxy` 是 subshell wrapper，可呼叫 shell functions；`proxy exec` 執行外部程式，
保留參數、stdio 與 exit code，不自動重跑命令。

`proxy-status` 分別報告環境設定與 session；`proxy-test` 才進行有界請求。
設定了 env、listener 可連、收到 HTTP response 是三種不同證據。

## SSH target

`proxy-on server` 在 foreground 完成 native SSH 認證，再建立該 shell 專用的 loopback
轉發並套用 env。密碼不交給 lazyclash 保存。每個 shell 有自己的 lease／control socket；
`proxy-off`、正常 exit 只清理自己的 session，既有使用者 ControlMaster 不受影響。

```sh
lazyclash proxy tunnel status
lazyclash proxy tunnel cleanup
```

SIGKILL／終端崩潰無法執行 shell exit hook；後續 on/status/refresh 或 cleanup 會依
owner PID 與啟動身份處理 stale lease，不根據可重用的 PID 任意殺程序。網路中斷時
session 顯示 unavailable，需要明確重連，不背景詢問密碼或偷偷改走 direct。

一般 `proxy env` 不建立短命 tunnel 然後輸出失效網址。SSH 持久 env 支援 HTTP／SOCKS5(H)；
HTTPS proxy 若需原 hostname 驗證，不會改成 localhost 並停用 TLS。直接可達的 HTTPS
proxy，以及工具內部保留 TLS hostname 的診斷／bootstrap transport，仍各有其用途。

## Docker consumer

容器的 localhost、Docker daemon 主機，以及 Buildx builder 可能是三個不同位置。
明確選擇 consumer 可達的 endpoint，再產生設定：

```sh
lazyclash proxy docker render --endpoint http://host.docker.internal:7890 \
  --format env-file --output /absolute/private/container-proxy.env
lazyclash proxy docker render --endpoint http://proxy.internal:7890 \
  --format compose --service app --scope both
lazyclash proxy docker test --endpoint http://proxy.internal:7890 --container app
lazyclash proxy docker doctor
```

上面的 `host.docker.internal` 是 Desktop 候選，不保證 loopback-only listener 可達。
工具不為此自動開啟 Allow LAN 或改 bind address。測試使用明確選定的既有 container，
或本地 probe image；不隱式 pull image。Container 通過不代表遠端 builder 已通過。

輸出格式包括 runtime env-file、指定 services 的 Compose environment/build.args、
build-args 與可檢查的 client JSON snippet。Project `.env`／Compose `--env-file`
是 interpolation input，不能當成已注入 container 的證據。Dockerfile 不應把代理
憑證寫入永久 `ENV`；proxy build args 是不同機制。

本功能不改 `~/.docker/config.json`、daemon 設定或重啟 Docker。chezmoi 仍是既有
client config 的管理者。Daemon pull 的代理與 Docker Desktop 設定依 doctor 指引
另外處理。自訂 CA 不會自動複製到容器，consumer 需要自己的 trust 設定。

chezmoi 的 legacy `docker-net`／`copilot-proxy` cache adapter 不輸出帶憑證的 URL，
因為舊 consumer 可能列印或保存 cache。這類 target 使用原生 `proxy-on/exec` 或明確
配置 consumer credentials。

依據：[Docker client proxy](https://docs.docker.com/engine/cli/proxy/)、
[daemon proxy](https://docs.docker.com/engine/daemon/proxy/)、
[Compose interpolation](https://docs.docker.com/reference/compose-file/interpolation/)、
[OpenSSH multiplexing](https://man.openbsd.org/ssh_config#ControlMaster)。
