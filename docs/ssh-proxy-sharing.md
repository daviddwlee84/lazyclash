# 雙向 SSH 代理與生命週期

Controller API 管核心；data proxy 承載 HTTP／SOCKS 流量。SSH 轉發後仍使用
提供代理那端的規則、群組與節點，不複製設定，也不自動開啟 TUN。

| 需求 | 指令 | 結束時機 |
|---|---|---|
| 本機使用遠端代理 | `proxy-on server` | 本機 shell 的 `proxy-off`／正常退出 |
| 遠端 shell 使用本機代理 | `lazyclash --target desktop proxy ssh server` | 遠端 shell 結束 |
| 一次遠端命令使用本機代理 | `lazyclash --target desktop proxy ssh server -- curl https://example.com` | 該命令結束 |
| 其他遠端 terminal 使用本機代理 | `lazyclash --target desktop proxy tunnel share server` | 分享指令 Ctrl+C／退出 |

```text
本機使用遠端：本機程式 → 本機轉發入口 → SSH -L → 遠端代理 → 出口
遠端使用本機：遠端程式 → 遠端轉發入口 → SSH -R → 本機代理 → 出口
```

## 分享本機代理

目的地是 SSH host alias；`--target` 選的是來源核心，不是目的地。
沒有明確來源時沿用本機 proxy 選擇／picker；`--endpoint` 亦支援普通代理。

```sh
lazyclash --target local-clash-verge-rev proxy ssh david_ubuntu
lazyclash --target local-clash-verge-rev proxy ssh david_ubuntu --clean-shell
lazyclash proxy ssh david_ubuntu --endpoint http://127.0.0.1:7897 \
  -- curl https://example.com

# 此命令保持前景；將輸出的 exports 貼到另一個遠端 terminal
lazyclash --target local-clash-verge-rev proxy tunnel share david_ubuntu \
  --remote-port 17897
```

預設由遠端分配可用 port。`--remote-port` 固定 HTTP／mixed port；不同 HTTP／SOCKS
來源可搭配 `--remote-socks-port`。同一 mixed 來源預設共用轉發。指定 port 被佔用時
失敗，不關閉別人的 listener。`share --json` 輸出一筆 ready JSON 後仍保持運行；
不能等待它退出後才使用輸出的 endpoint。

遠端需要 OpenSSH，以及 Linux 的 listener 資訊或 macOS 的 `lsof`，不需要 lazyclash。
啟動先確認來源 TCP 可達，再認證、建立轉發並檢查實際 listener；ready 表示 tunnel
已建立，不代表所有網站均可存取。`GatewayPorts=yes` 會強制 wildcard，工具發現後
立即關閉自己的 tunnel；應使用 `no` 或 `clientspecified`。檢查發生在 listener
建立後，因此不宣稱完全沒有短暫開放窗口；工具不修改 sshd／firewall 設定。

第一版限從本機可達的無認證 HTTP／SOCKS data proxy；不接受 SSH source、HTTPS
proxy endpoint、data-proxy credentials 或自訂 proxy CA。來源 controller 的 API
secret 不受此限制。HTTP proxy 的 CONNECT 仍可存取 HTTPS 網站。

## 遠端 shell 與命令

預設啟動遠端原本的 login shell，保留正常提示字元與設定。其啟動檔、direnv 或
使用者後續操作仍可能覆寫 proxy env。`--clean-shell` 啟動固定 `/bin/sh -i`，清除
`ENV/BASH_ENV`，不載入這個子 shell 的使用者啟動檔；既有 SSH 登入政策仍生效。
此選項不能與 `-- COMMAND` 混用。

單次命令在 SSH command shell 初始化後套用環境，保留 argv、binary stdin／stdout
和退出碼；shell operators 要明確使用 `sh -c`。程式不支援 proxy env 或 `NO_PROXY`
符合目的地時，仍可能不經此代理。遠端既有 `NO_PROXY/no_proxy` 保留。

`proxy ssh` 的 stdout 屬於遠端程序，不接受 `--json`。互動 shell 需要 TTY；非互動
呼叫提供 `-- COMMAND`，SSH 認證不會在 JSON／無 TTY 輸入中詢問密碼。

每次分享擁有自己的 master；使用者原本的 ControlMaster 不會被關閉。認證沿用
原生 OpenSSH，包含 host-key、key、password 與 ProxyJump。連線失敗不重連、不改走
direct，也不重跑遠端命令。正常退出／取消會清理；SIGKILL 後可能暫留，下一次分享
或 `proxy tunnel cleanup` 按程序身分回收。可用 `proxy tunnel status/stop ID` 管理。

## 背景服務不能借用短期出口

```sh
lazyclash --target desktop proxy env --consumer service --json
lazyclash proxy env --endpoint http://127.0.0.1:7897 --consumer service
```

`--consumer process` 是預設；`service` 拒絕已知依賴 shell／前景 SSH tunnel 的入口。
本機普通代理不因使用 `proxy-on` 就被拒絕。檢查比對 private registry 與 endpoint-bound
`LAZYCLASH_PROXY_ORIGIN`；分享輸出的這個非秘密標記應與 exports 一起保留。
它不是授權機制，亦無法追蹤任意外部 SSH tunnel；通過檢查不保證 endpoint 永遠可用。

chezmoi 的 Copilot 啟動與 `docker-net on` 在副作用之前使用同一檢查，不把短期入口
保存給背景服務。auto 模式的「未配置代理」可以保持原有無代理行為；解析歧義、
失效 session、認證或生命週期拒絕則回報錯誤，不偷偷換用 system proxy。
沒有 lazyclash／舊版 CLI 仍走相容路徑；既有 shell functions 不在本版大幅遷移。

機器介面：未配置代理是 exit `4`／`proxy-not-configured`；短期入口不適用服務是
exit `1`／`proxy-temporary`。明確指定不存在的 target 仍是錯誤，不等同未配置。

參考：[OpenSSH forwarding](https://man.openbsd.org/ssh)、
[GatewayPorts](https://man.openbsd.org/sshd_config#GatewayPorts)。
