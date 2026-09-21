# Tailscale 出口與私有 proxy

`tailnet` 管理已安裝並登入 Tailscale 的裝置。Exit Node 為整台 client 提供 Internet
出口；Tailnet proxy 讓指定應用或 Mihomo 節點使用遠端出口，保留 client 的分流。

| 模式 | 資料路徑 | 適合用途 |
|---|---|---|
| Exit Node | OS routing → Tailscale → 遠端系統出口 | 整台電腦換出口 |
| Serve TCP proxy | HTTP／SOCKS client → Tailscale Serve → 遠端 loopback proxy | 私有 TCP proxy，預設選項 |
| Tailnet IP proxy | Client → 遠端 Tailnet IP 上的 proxy listener | 需要原生 UDP 的協議 |

遠端只有瀏覽器設定 proxy，不表示 Exit Node 轉送的流量會使用它。Exit Node 需要可用的
系統出口；gateway 可以明確配置既有 HTTP／SOCKS upstream。Tailscale 的 direct、DERP
或 peer relay 連線也必須實際可達。工具回報觀測結果，不把 Online 當作出口已驗證，
也不承諾任何地區的固定可用性或速度。[Exit Node](https://tailscale.com/docs/features/exit-nodes)、
[連線方式](https://tailscale.com/docs/reference/connection-types)。

## 保存與管理範圍

裝置、SSH alias、stable peer ID、出口及 proxy 設定保存在與 VPS 共用的 `servers.toml`，
可用 `--servers-config` 選擇獨立 inventory。認證資料、操作快照及復原紀錄放在私有
state directory。Mihomo controller targets 與 Tailnet 裝置是不同物件。

SSH alias 必須實際連到選定的 Tailscale peer。每次操作重新核對身分；不能因為名稱或
IP 看起來相同就接管另一台機器。只有本工具建立並記錄的服務及 mapping 可以被移除。

`--json` 不開啟互動表單或收集密碼。需要 SSH／sudo 登入時，回到互動終端讓 OpenSSH
或 sudo 處理；不使用 `sudo -S`，不保存密碼。變更沿用預覽與 digest 綁定的 apply。

## Exit Node

出口端要先啟用 Linux IPv4／IPv6 forwarding 並公告出口，再由 Tailnet 管理員批准，
最後由每台 client 選用。自訂存取政策還需要允許 `autogroup:internet`；能 SSH 到 peer
不代表有使用 Internet 出口的權限。[官方設定流程](https://tailscale.com/docs/features/exit-nodes)。

```sh
lazyclash tailnet peers --json
lazyclash tailnet exit setup rpi --ssh rpi --interactive
lazyclash tailnet exit status rpi --json
lazyclash --target desktop tailnet exit use rpi --interactive
lazyclash tailnet exit release --interactive
```

完整參數但沒有 `--yes` 時只輸出預覽。Script 先讀取預覽的 `digest`，再帶入同一組
參數及 `--yes --expect DIGEST`；互動流程在顯示預覽後提供確認。

`setup` 的遠端設定與 `use` 的本機選用分開復原。等待管理員批准是可續接狀態，不算完成
client 出口驗證，也不要求在短暫的 rollback deadline 內完成批准。

`enable`／`disable` 控制遠端出口公告；`use`／`release` 控制本機選用。`release` 在設定
仍符合本次寫入結果時恢復先前選用及 TUN。若 core 已重啟或被編輯，明確執行 `release`
可恢復未變更的 Tailscale 偏好，保留新的 core 設定並回報 `released_tun_preserved`；
若出口偏好也被外部修改則回報衝突。自動逾時復原維持嚴格的身分與設定檢查。停止出口不呼叫
`tailscale down`，也不停止 `tailscaled`，因此不主動拆除 SSH 所需的 Tailnet。
移除設定不盲目關閉可能由 Docker 或其他 router 共用的 forwarding。

### Mihomo TUN 交接

選用 Exit Node 前，檢查其他預設路由管理者。已確認的本機 Mihomo TUN 可由 runtime API
暫停並保存快照；未知 VPN 不會被自動關閉。mode、system proxy 及 DNS 偏好維持原值。
LAN access 預設關閉，需要時明確啟用。

Clash Verge 的 TUN 暫停只作用於目前 runtime。其原生設定可在 profile reload、core 或
app 重啟後重新開啟 TUN。工具保存 core 身分及設定證據，於後續 status／操作偵測衝突，
不在背景反覆覆寫 native owner，也不跨越已改變的 owner generation 自動恢復 TUN。
需要重啟後仍停用 TUN 時，請在 Verge 原生 UI 設定。

驗證成功後保留 Exit Node 選用。出口離線不自動切回直連。測試系統 HTTPS、DNS 與既有
本機 proxy 的出口，避免把某一個 proxy request 成功誤當作整機 routing 正確。
一般 Tailnet route exclusions 無法解決兩個全流量 VPN 的競爭。
[官方 VPN 共存限制](https://tailscale.com/docs/reference/faq/other-vpns)。

## Tailnet proxy

預設部署獨立、帶認證的 Mihomo HTTP／SOCKS gateway，controller 與 proxy 聽在 loopback，
再以 `tailscale serve --bg --tcp` 建立私有入口。Serve mapping 持久存在；停止分享只移除
該 mapping，不執行 `serve reset` 或影響其他服務。Serve raw TCP 不提供一般 UDP forwarding。
[Serve 指令](https://tailscale.com/docs/reference/tailscale-cli/serve)。

直接綁定 Tailnet IP 的模式可提供協議本身的 UDP 能力。原生服務只能綁定已確認存在的
Tailnet 地址；Docker 在 host publish 綁定該地址，不要求 bridge container 擁有該 IP。
地址遺失時報錯，不退回 `0.0.0.0` 或 `::`。Management controller 維持 loopback。
SOCKS UDP datagram 不攜帶 TCP 的帳號密碼；UDP 的存取限制來自 Tailnet 身分、access
policy 及指定地址。TCP HTTPS 測試成功不代表已驗證 UDP 出口。

不需要 Exit Node 的機器可單獨註冊並部署 proxy：

```sh
lazyclash tailnet add home --ssh home-server --interactive
lazyclash tailnet proxy deploy home-proxy --node home --interactive
lazyclash tailnet proxy status home-proxy --json
lazyclash tailnet proxy export home-proxy --format mihomo
lazyclash --target desktop tailnet proxy connect home-proxy --interactive
```

Gateway 的出口可以是遠端直接出網，或明確指定 HTTP／SOCKS upstream。系統不從
`HTTP_PROXY` 猜測，不允許 gateway 把自己當成 upstream。分享既有外部 proxy 時只擁有
分享入口，不接管該 proxy 的啟停或設定。這些流程不開啟公開 Internet 的 Funnel。

匯出支援 Mihomo node、完整 starter 與 client bundle，並能透過既有 source import 流程
加入 client。匯出包含 proxy credentials，應視為私有資料；附帶 Tailnet 存取前提，不包含
Tailscale auth key 或全 Tailnet inventory。HTTP URL 仍解讀為 subscription，不新增模糊的
自動 endpoint 辨識。Exit Node 分享的是裝置及選用指引，不是 proxy URI。

## 診斷與驗證

分別檢查 peer 可達性、direct／relay transport、SSH、proxy listener、HTTP／HTTPS、DNS
與出口 IP。保存測試時間，區分已公告、待批准、可選用、目前選用及出口已驗證。
Proxy export 成功不代表消費端已有 Tailnet 存取權；必須從實際 client 驗證。

透過 SSH `-L` 使用遠端 loopback proxy 仍可用既有 `proxy` 指令，但它屬於 shell／process
生命週期，不應把短暫的本機轉送 port 匯出成永久 server endpoint。
參考[雙向 SSH proxy](ssh-proxy-sharing.md)及[VPN／TUN 共存](vpn-coexistence.md)。
