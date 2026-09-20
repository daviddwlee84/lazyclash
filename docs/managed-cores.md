# 安裝與管理 Mihomo client

`setup` 建立一個 lazyclash-owned client，記錄 binary／image 版本、服務、設定來源與
target。既有 Verge、其他 system service 和未知容器仍由原 owner 管理。

```sh
lazyclash setup
lazyclash cores list --json
lazyclash cores status workstation --json
lazyclash cores configure workstation --interactive
```

Wizard 可選本機或 SSH、native 或 Docker，匯入 share links、節點訂閱或完整 YAML，
配置群組／starter、TUN 與 system proxy，最後檢查具體變更再套用。只提供部分 business
參數時不自動進 wizard；使用 `--interactive` 明確補齊。JSON 模式不提示 sudo／SSH 密碼。

## 可重現的 CLI 流程

```sh
lazyclash --ssh home-server setup home-core --backend native \
  --input-kind links --input /absolute/private/nodes.txt --preset cn-split --json

# 檢查上一步的版本、端口、來源、權限、blockers 和 digest 後：
lazyclash --ssh home-server setup home-core --backend native \
  --input-kind links --input /absolute/private/nodes.txt --preset cn-split \
  --yes --expect REVIEWED_DIGEST
```

Native 使用固定官方版本與 asset SHA-256；Docker 固定官方 image digest，要求已有可用
daemon／Compose，不隱式安裝 Docker。預設使用 loopback controller／mixed port、
生成 API secret，遇到端口衝突要求更換，不停掉原有服務。

Proxy 模式使用 user service；需要 TUN 時使用 system scope 和 root-owned 檔案。
`--boot` 控制可用 host policy 下的 boot/login 自啟；Linux user service 不自動開啟 linger。
系統權限交給原生 sudo／SSH，TUI 本身維持一般使用者權限。

Docker bridge 模式在 container 內監聽對應端口、只發佈到 host loopback；其 container
listener 不能直接當成外部 host endpoint。Host TUN 支援矩陣與 VPN 檢查見
[VPN 共存](vpn-coexistence.md)。

成功後自動加入 targets，分別回報 service、API 與 proxy request 狀態。Proxy request
失敗不等於安裝不存在；保留 receipt 與私人資料，先看 `cores status` 再決定下一步。
Configure 保留核心版本、backend、service scope／身份及 listener ports；遷移這些
邊界使用另一個明確規劃的 instance。

## Starter、地區分流與 GitHub 不可達

```sh
lazyclash rules preset list --json
lazyclash --target home-core rules preset apply cn-split --json
lazyclash --target home-core rules preset update --json
```

`cn-split`：本機／VPN bypass、reject／direct／proxy 明確分類、CN domain／IP 直連，
其餘交給 PROXY。可選 AI、Apple、媒體分類並明確映射到 policy；不從節點名稱猜地區。
`simple`：本機／VPN bypass，其餘 PROXY。完整 YAML 預設 `preserve`，避免默默替換使用者規則。

這些規則資料隨 binary 附帶，使用本地 providers，不需要首次從 GitHub 下載 geodata。
來源是 clash-rules 的 immutable `rules-<SHA-256>` artifact，逐檔驗 hash，保留原始
manifest、lock 與授權。手工規則與 mirrored geo data 的授權分開標示。
`preset update` 使用目前 lazyclash binary 所附的快照；啟動不會浮動更新規則。

Core binary／image 和節點本身仍需可取得。可選已存在 target 作為明確 bootstrap data
proxy，或使用已驗證的本地 artifact／image archive；不能依賴尚未啟動的新 core 下載
它自己需要的檔案。下載失敗保留草稿／舊資料，不切換到隱含環境代理。

訂閱是 node provider，初始可用快照納入私人設定；完整 YAML 另走匯入路徑並檢查
provider、檔案與 geodata 依賴。這裡的「離線 starter」是規則建立不用連 GitHub，
不代表無網路也能存取代理出口。

參考 [clash-rules 發佈契約](https://github.com/daviddwlee84/clash-rules/blob/main/docs/release-pipeline.md)
與 [第三方資料說明](https://github.com/daviddwlee84/clash-rules/blob/main/THIRD_PARTY.md)。
Docker 範例參考 [DockerCompose-V2Ray 的 client 子目錄](https://github.com/daviddwlee84/DockerCompose-V2Ray/tree/9e6f3b957edbbaf2bbcfd9deea8d871873069e56/clients/mihomo-docker)，
不執行其 Xray server／防火牆部署。

## 停止與移除

```sh
lazyclash cores stop home-core --json
lazyclash cores stop home-core --yes --expect REVIEWED_DIGEST
lazyclash cores remove home-core --json
```

Start／stop／restart／remove 都先預覽再套用。只有已記錄且重新核對的 owner 可操作；
remove 預設保留私人設定、備份與操作紀錄。System proxy 還原遇到使用者後續改動時回報
衝突，不強制蓋回舊設定。未 ACK 的新 TUN 會被 rollback 並避免於下一次 boot 自動復活。
