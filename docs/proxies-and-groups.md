# 節點、群組、複製與分享

`proxies list` 是 runtime 狀態；節點的 server、password、UUID、TLS 和 transport
需要從完整設定來源讀取。只連 external API 時可以監控、切換和測延遲；要編輯或
產生可用的分享連結，先綁定來源。`source_config` 仍只是 API 憑證發現參照。

## 綁定來源

TUI 的 `:` 選單提供 **Bind node / group configuration source**，CLI 也有同一個 wizard：

```sh
lazyclash --target desktop configs source set --interactive
lazyclash --target desktop configs source show --json
```

Standalone YAML 使用已註冊的完整設定、實際核心 binary 和 home：

```sh
lazyclash --target server configs add main --path /srv/mihomo/config.yaml
lazyclash --target server configs source set --kind native --config-id main \
  --binary /usr/local/bin/mihomo --home /srv/mihomo
```

Linux native core 若無法使用 bubblewrap，可明確指定 Docker 作為驗證 sandbox：
在 `configs source set --kind native` 加上 `--validation-docker-host unix:///...`
與 `--validation-image sha256:...`（必須是已存在的完整 image digest）。它驗證相同
core bytes、停用網路與 capabilities，保留 host 檔案權限；不拉取 image、不修改
Docker context 或系統的 user-namespace 限制。這只是驗證 backend，實際 client 仍為 native service。

Docker 必須分清 host source 與 container reload path；這些都是選定 SSH host／daemon
上的位置。以下是結構範例，請使用實際 mount 與 binary：

```sh
lazyclash --target server configs source set --kind docker \
  --container mihomo --host-path /srv/mihomo/config.yaml \
  --core-path /root/.config/mihomo/config.yaml \
  --binary /mihomo --home /root/.config/mihomo
```

綁定會核對 container、image、daemon locality 與 bind mount。Directory bind 可看見
原子替換的新檔案；single-file bind 可能仍持有舊 inode，需要由 container owner
重新掛載並驗證。缺少 Docker 權限或無法隔離驗證時，在寫入前回報。

Rootless Docker 使用 `--docker-host unix:///run/user/UID/docker.sock`，固定選定主機上的
daemon，不修改 Docker 的全域 context。若同時綁定 [既有 client service](client-services.md)，
預覽會揭露 single-file bind 所需的精確容器重啟；寫入後先比對容器內外雜湊，再確認 runtime。

Clash Verge Rev 2.5.2 使用目前 profile 的既有 Proxies／Groups companions：

```sh
lazyclash --target desktop configs source set --kind verge \
  --data-dir '/absolute/Clash Verge data directory' \
  --profile PROFILE_UID --owner-version 2.5.2
```

這與 `rules source set` 的規則寫入範圍獨立。修改 target 的 controller／SSH host
會清除 source binding，避免把舊檔案套到另一個核心。`configs source clear` 只解除綁定。

## 新增與編輯

Proxies 頁的 `n` 新增、`e` 編輯、`y` 分享；其他動作位於 `:`，也有滑鼠按鈕。
CLI 的 bare add/import 或明確 `--interactive` 使用相同表單：

```sh
lazyclash --target desktop proxies add
lazyclash --target desktop proxies import --interactive
lazyclash --target desktop proxies edit 'My node' --interactive
lazyclash --target desktop groups add --interactive
lazyclash --target desktop groups edit PROXY --interactive
```

群組表單分開呈現有順序的 `proxies` 與 provider `use`，提供 select、url-test、fallback、
load-balance 常用選項，並保留進階 YAML。Runtime 展開後的 `all` 不能反推原本的
provider／filter 定義。Edit 保留名稱；另取名稱使用 Duplicate，避免漏改跨物件引用。

腳本先預覽，再帶回精確 digest 套用。節點憑證建議從私人檔案或 stdin 輸入：

```sh
lazyclash --target server proxies import --file /absolute/private/nodes.yaml --json
lazyclash --target server proxies import --file /absolute/private/nodes.yaml \
  --yes --expect REVIEWED_DIGEST --json
lazyclash --target server configs verify RECEIPT_ID --json
```

預覽列出遮蔽敏感欄位的實際變更；原始檔／上下文改動會使舊 digest 失效。保存、
核心 reload 和網路可用性是不同結果。遇到 partial／unknown 結果先 inspect／verify；
不要重送整個變更。`configs restore RECEIPT_ID --yes` 會檢查目前檔案仍符合操作紀錄。

新增／匯入表單可逐一選取來源群組，不需要手打逗號分隔的名稱。`--create-group NAME`
可在同一次預覽中建立包含新節點的 select 群組；routing rules 與父群組不會自動修改。
其他群組類型沿用 `groups edit`。Preview 會先檢查協定與 core 相容性，再執行隔離驗證；
Classic Clash 無法使用的 VLESS／REALITY 不會等到寫入後才回報。

`proxies import --adopt-existing` 與 `servers connect --adopt-existing` 只沿用完整定義一致的
同名節點，仍可加入選定群組。不同內容會拒絕覆蓋，需另取名稱。完全無配置變更時，
只保存與驗證 receipt，不重新載入核心。Server connection 紀錄保留節點到 VPS 的關聯，
供 [雲端用量](vps-usage.md) 查詢使用。

Verge 保存後要在原生 UI 重新啟用 profile，再 Verify。修改其私人節點可以原位保存；
覆寫完整訂閱 profile 的同名節點可能需要同時建立 group overrides 以保留成員，
預覽會列出影響。這些 group overrides 也會遮蔽後續訂閱對同名群組的改動。
動態 provider 的節點則應 Duplicate 成私人節點，不直接改下載快取。
後續 Merge／Script 仍可能覆蓋結果，因此驗證包含生成設定與 runtime 結構。

## 多個 targets 匯入

`proxies add/import --interactive` 使用可搜尋的多選列表：輸入 → targets → 各 target
自己的群組／新群組 → 全部預覽 → 一次套用。Space 勾選，`/` 搜尋，Enter 下一步；
Esc 回上一步保留草稿，Ctrl+C 取消。最後 review 的 Back 回到編輯，Apply 才開始寫入。
明確 `--target` 或 TUI 當前 target 會預先勾選，仍可調整；未指定則不預勾。
缺少來源時可進入既有 binding wizard，返回後繼續匯入。

TTY 中新增／匯入未指定 target 時會自動引導選擇。完整的指定 target 指令保持既有
preview 行為；`--yes --expect`、非 TTY 與 JSON 不自動開 wizard。
Target 名稱也可以用 `--target <Tab>` 補全，補全只讀本機註冊資料。

腳本用 `--destinations` 指定每個 target 的群組；此旗標與 `--target`、`--group`、
`--create-group` 互斥。目的地檔案不放節點憑證：

```json
[
  {"target": "desktop", "groups": ["PROXY", "Auto Select"]},
  {"target": "server", "groups": ["Outbound"], "create_groups": ["Private, 東京"]}
]
```

```sh
lazyclash proxies import --file /absolute/private/nodes.yaml \
  --destinations destinations.json --json
lazyclash proxies import --file /absolute/private/nodes.yaml \
  --destinations destinations.json --yes --expect BATCH_DIGEST --json
```

批次 digest 綁定所有目的地與輸入。套用前重新檢查全部來源，再依 target ID 順序
逐一套用。每個 target 使用自己的認證；互動模式指定的 credential override 只影響
明確 `--target` 的那一個。單一 target 失敗或結果不明時停止後續寫入，輸出各自的
receipt 與未執行項目；已完成的變更保留，不會自動重試或回滾。

`remarks` query 可作為節點名稱的相容欄位，例如 `vless://…?remarks=台北`。
`#名稱` 優先於 `remarks`；VMess JSON 仍使用 `ps`。匯出維持既有標準形式，未知
連線參數仍會報錯；這不是對所有 Shadowrocket URL 變體的相容承諾。

群組的上下游與反向引用可用 [配置拓樸](routing-topology.md) 檢查。

## 複製與分享

```sh
lazyclash proxies copy desktop server 'My node' --name 'Private copy' --group PROXY
lazyclash --target desktop proxies copy 'My node' --interactive
lazyclash --target desktop proxies export 'My node' --interactive
lazyclash --target desktop proxies export 'My node' --format url --clipboard
lazyclash --target desktop proxies export 'My node' --format url --qr
lazyclash --target desktop proxies export 'My node' --format url --qr --output /absolute/private/node.png
```

Copy 會分別解析兩端的認證，並檢查名稱、群組及檔案／dialer 依賴。目的地寫入也需要
review／digest；來源不會被刪除。

YAML／JSON 是完整 **Mihomo node mapping**。分享 URL 支援 SS、VMess、VLESS、Trojan、
Hysteria2；QR 包含同一份 URL。某些 Mihomo 欄位無法用協議 URL 表達時，工具拒絕
有損輸出並建議 YAML／JSON，不宣稱所有 Shadowrocket JSON 都相容。

Export、Copy URL／JSON、clipboard、QR 是明確的憑證輸出操作。一般 list、preview、
錯誤與 receipt 不輸出憑證；export 檔案使用私人權限，且不覆寫既有檔案。

依據：[Mihomo API](https://wiki.metacubex.one/api/)、[群組配置](https://wiki.metacubex.one/config/proxy-groups/)、
[provider 配置](https://wiki.metacubex.one/config/proxy-providers/)、
[Verge 2.5.2 sequence 實作](https://github.com/clash-verge-rev/clash-verge-rev/blob/v2.5.2/src-tauri/src/enhance/seq.rs)。
