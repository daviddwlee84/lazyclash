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

Verge 保存後要在原生 UI 重新啟用 profile，再 Verify。修改其私人節點可以原位保存；
覆寫完整訂閱 profile 的同名節點可能需要同時建立 group overrides 以保留成員，
預覽會列出影響。這些 group overrides 也會遮蔽後續訂閱對同名群組的改動。
動態 provider 的節點則應 Duplicate 成私人節點，不直接改下載快取。
後續 Merge／Script 仍可能覆蓋結果，因此驗證包含生成設定與 runtime 結構。

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
