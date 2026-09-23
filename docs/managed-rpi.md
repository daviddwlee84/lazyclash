# 受管 RPi-ImmortalWrt

`rpi-immortalwrt` 將節點、群組、規則、Selector 切換與區網裝置觀測交給
RPi-ImmortalWrt 專案的 broker。安裝、網路、安全防火牆、Nikki 生命週期與回復
仍由該專案管理。使用前須已完成該專案的嚴格 SSH、network／proxy 確認與私人 CA TLS controller 設定。

## 註冊與來源

先在本機建立 target。以下使用占位路徑與位址；controller、CA 與 SSH transport
必須和既有私人 connection JSON 一致。API secret 以既有 `0600` 私人檔案參照，
不要放入 TOML、命令列值或公開 YAML。

```sh
lazyclash targets add pi \
  --controller https://192.0.2.1:9090 \
  --ca-cert /absolute/RPi-ImmortalWrt/private/pki/ca.crt \
  --secret-file /absolute/RPi-ImmortalWrt/private/controller.secret \
  --rpi-project-dir /absolute/RPi-ImmortalWrt \
  --rpi-connection-file /absolute/RPi-ImmortalWrt/private/managed-pi.json
lazyclash --target pi configs source set --kind rpi-immortalwrt
lazyclash --target pi rules source set --kind rpi-immortalwrt
lazyclash --target pi --read-only
```

`targets edit pi` 也接受兩個 `--rpi-*` 旗標。設定會保存獨立的
`[targets.managed_rpi]`，包含絕對 `project_dir` 與 `connection_file`。兩個來源
只接受 `kind = "rpi-immortalwrt"`，不接受 generic binary、home 或 source path。
`configs source clear` 解除節點／群組來源後，受管 owner 邊界仍保留。

Broker 使用本機 `python3 PROJECT/scripts/device/proxy_manage.py`，由 connection JSON
執行專案的嚴格 SSH。連 API 前先核對 broker 的 controller、CA 與 SSH transport，
失配即停止。請用 `--target pi`；已知受管 endpoint 不接受臨時 `--controller`。
connection、broker snapshot 及 broker receipt 必須位於專案 `private/` 內，為
`0600`、單一 hard link、無 symlink 的普通檔案。

## 編輯、確認與回復

沿用既有節點／群組 UI 或 CLI，先預覽再以精確 digest 套用：

```sh
lazyclash --target pi proxies edit 'Node name' --interactive
lazyclash --target pi proxies import --file /absolute/private/nodes.yaml --json
lazyclash --target pi proxies import --file /absolute/private/nodes.yaml \
  --yes --expect REVIEWED_DIGEST --json
lazyclash --target pi rules add-domain example.com --via PROXY --json
lazyclash --target pi rules add-domain example.com --via PROXY \
  --yes --expect REVIEWED_DIGEST --json
```

预覽不停止 Nikki；套用完整 profile 變更可能暫停代理，broker 會顯示此影響並走
RPi-ImmortalWrt 的驗證、交易、嚴格 reconnect 確認與回復流程。預覽綁定 profile、
network、boot 與 core identity；context 改變須重新預覽。來源只有 `proxies`、
`proxy-groups` 與 `rules` 可編輯，controller 與網路設定仍由專案 owner 決定。

節點／群組操作使用 `configs verify RECEIPT_ID`、`configs restore RECEIPT_ID --yes`；
規則操作使用 `rules verify RECEIPT_ID`、`rules restore RECEIPT_ID --yes`。
遇到 `owner_result_unknown`，保留 receipt，先 verify，勿自動重送寫入。
Restore 直接交由 broker 核對與回復，不要求失敗後的 proxy 先恢復健康。
Lazyclash receipt 只參照 broker receipt，不另存完整私人 profile。

TUI Selector 切換也透過 broker 核對既有 group/member 與切換結果。
Generic 完整 YAML reload、runtime mode／TUN／Allow LAN／listener patch、provider
更新與 healthcheck 均受 owner 邊界阻擋。Generic setup／cores 不接管已知的受管
target 或主機，既有 client service 操作同樣不適用。`--read-only` 仍禁止切換與套用。

## 區網裝置 inventory

```sh
lazyclash --target pi inventory
lazyclash --target pi --read-only inventory --json
```

TUI 的 `:` 選單提供「受管 RPi：查看區網裝置 inventory」。資料來自 Pi 的 DHCP
租約、IPv4 鄰居快取與 hostapd；沒有主動掃描。`associated`、`reachable`、`failed`
與 `observed` 表示不同觀測證據。租約或快取仍存在，不代表裝置目前在線；列表亦非
所有區網裝置的完整清冊。`complete` 表示這次支援的來源讀取完成。

## 開發版本與驗證範圍

```sh
go build -o bin/lazyclash-managed-rpi ./cmd/lazyclash
bin/lazyclash-managed-rpi --target pi --read-only inventory --json
```

此路徑可並存測試，不會替換 Homebrew binary。Go fixture 測試只證明 owner dispatch、
輸入與路徑保護及介面行為；實機交易、回復與客戶端流量仍須分別驗收。
