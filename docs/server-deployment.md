# 服務端、VPS 與 SSH 部署

`setup` 安裝 Mihomo **client**；`servers deploy` 安裝代理 **server**。VPS 與
server 記錄存在獨立的 `servers.toml`，不會冒充 Mihomo controller target。
TUI 的 `:` → **Servers / VPS** 使用相同 CLI 操作，先顯示本地記錄，再按需更新狀態。

```sh
lazyclash servers recipes --json
lazyclash vps catalog --json
lazyclash vps estimate --provider vultr --region nrt --plan vc2-1c-1gb --egress 1524 --json
lazyclash servers deploy                 # 互動選主機、配方、部署與分享
lazyclash vps create                     # 只建立雲端主機的 wizard
lazyclash vps list --json
lazyclash servers list --json
```

## SSH / homelab

遠端首版支援 Ubuntu 24.04 LTS、amd64／arm64 與 systemd。管理使用 OpenSSH，
保留既有 host alias、port、identity、jump host 和 host-key 檢查。服務管理需要
root SSH 或可以非互動執行固定 Python helper 的 sudo；lazyclash 不保存 SSH 密碼。

```sh
lazyclash vps register home --provider homelab \
  --ssh-host home-server --public-host proxy.example.net

# 先檢查公開位址、端口、遠端環境與固定 artifact：
lazyclash servers deploy home-reality --host home \
  --recipe vless-reality --backend native --json

# 帶回上一步實際顯示的 digest：
lazyclash servers deploy home-reality --host home \
  --recipe vless-reality --backend native --yes --expect REVIEWED_DIGEST
```

`--public-host`／`--public-port` 是 client 連線端點；`--listen-port` 是主機的監聽
端口；SSH alias 可以指向私網。它們不需要相同。NAT 的外部轉發須另外配置，
Hysteria2 必須轉發 UDP。CGNAT、ISP 入站封鎖、DNS 或 router forwarding 不由
lazyclash 自動修正；部署成功和從 client 網路可用是不同結果。

主機已有服務占用端口、同名 systemd unit／Compose project 或未知所有權時會停止。
新建且由 lazyclash 管理的 VM 可將 Docker 安裝納入計畫；既有主機選 Compose 時
要求已有可用 Docker Engine／Compose。預設 native 可減少常駐元件；不宣稱容器
必定比較慢。單服務的 1 vCPU／1GB RAM 是起點，實際吞吐、CPU 和記憶體需量測。

## 協議配方

| ID | 服務與入口 | 條件 |
|---|---|---|
| `vless-reality` | Xray；VLESS + TCP/RAW + REALITY + `xtls-rprx-vision` | 預設；不需要自有網域／憑證；REALITY target 從 VPS 驗證 TLS |
| `hysteria2` | Hysteria2；QUIC/UDP + TLS | UDP 可達、DNS 網域和憑證；沒有 TCP fallback |
| `legacy-vmess-ws-tls` | Xray VMess AEAD + WS、nginx TLS | 保留歷史 Azure 組合；需要網域、TCP 與憑證續期 |

VLESS 是協議、TCP／WS 是傳輸、REALITY／TLS 是安全層、Vision 是 flow。
REALITY 須讓 Xray 直接處理連線，不能放在一般 HTTP CDN 或 nginx TLS termination 後。
Hysteria2 與 legacy 配方使用 ACME HTTP challenge，TCP 80 須可達，續期後重新載入
對應服務。首版不使用跳過憑證驗證、不自動配置 DNS provider、不啟用 port hopping。
Trojan／XHTTP 可作後續配方；目前未宣稱支援其部署／匯出組合。

所有 binary 以官方 release SHA-256 驗證；image 解析成不可變 digest。
版本在預覽時具體化，不在重啟時浮動升級。移除服務不會解除安裝共用 OS 套件。

來源：[Xray REALITY](https://xtls.github.io/en/config/transports/reality.html)、
[VLESS flow](https://xtls.github.io/en/config/inbounds/vless.html)、
[Hysteria2](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)、
[Mihomo VLESS](https://wiki.metacubex.one/en/config/proxies/vless/)。

使用者回報已驗證的是歷史 Azure + VMess/WS/TLS；DockerCompose-V2Ray 的
`9e6f3b957edbbaf2bbcfd9deea8d871873069e56` 另記錄了新 REALITY 配方的臨時 VM 測試。
這兩者與 lazyclash 實際測試結果分開，不能自動視為目前線路仍然可用。
[原始遷移與驗證紀錄](https://github.com/daviddwlee84/DockerCompose-V2Ray/blob/9e6f3b957edbbaf2bbcfd9deea8d871873069e56/docs/REALITY-MIGRATION.md)。

## VPS 選型與費用

以下是 **2026-09-21 查詢的報價快照**；按地區、庫存與帳戶條件重新核對，
不含稅、額外備份及其他資源。中國大陸線路需從自己的 ISP、地區與晚高峰實測。

| 方案 | 資源與價格 | 流量與定位 |
|---|---|---|
| Oracle Always Free | 符合 home region／tenancy 累計額度時免費 | 10TB outbound；可能無容量或回收閒置 VM；優先檢查 |
| RackNerd special | 1GB／20GB SSD，$21.99／年；2GB／35GB，$35.99／年 | 廣告列 3TB／5TB 月流量；確認計量規則、年付與機房後走 SSH |
| Vultr | 1 vCPU／1GB／25GB，約 $5／月 | 1024GB outbound；多個亞洲 region；超額 $0.01/GB |
| Linode / Akamai | Nanode 1GB／25GB，約 $5／月 | 1000GB outbound；標準 region 超額 $0.005/GB |
| DigitalOcean Droplet | 512MiB $4／月；1GiB $6／月 | 500／1000GiB outbound；超額 $0.01/GiB；後者是均衡起點 |
| Azure | 查所選 region 的小型 B-series；VM、磁碟、static IPv4 分項 | `az` 自動建機；按完整固定成本排序，流量另計 |
| AWS Lightsail | 查所選 region 的 Linux／IPv4 bundle，至少 1GiB RAM | `aws lightsail`；固定月費，inbound＋outbound 共用 allowance |
| AWS EC2 | 查 T4g／T3a／T3 micro 等小型 burstable VM | `aws ec2`；compute、gp3、EIP、流量分項，CPU credits 使用 Standard |

Oracle 只使用 Always Free A1 配方；目前保守限制為 tenancy 合計 2 OCPU／12GB
RAM、200GB boot/block storage，並查當月用量。免費額度、trial credits、配額和
實際機房容量分別處理；查不到必要資料就不建立，不會自動改用付費 shape。
未提供 subnet 時可建立帶操作標記的 VCN／internet gateway／route table／
security list／public subnet，不建立付費 NAT gateway。重用的網路保留原所有權。
新建 Oracle VM 另套用預覽中列出的固定 cloud-init：保留平台原本的 iptables
規則，加入 TCP 80／443 和 UDP 443，並用專屬 systemd oneshot 於開機重建。
initializer 版本和 SHA-256 綁定在建機 digest；既有 VM／homelab 不套用此步驟。
自訂其他代理端口仍需另行審查防火牆。
[Oracle Ubuntu 主機防火牆說明](https://docs.oracle.com/en-us/iaas/Content/developer/apache-on-ubuntu/01oci-ubuntu-apache-summary.htm)。

自動建機使用已登入的官方 CLI：`oci`、`vultr-cli`、`linode-cli`、`doctl`、
`az`、`aws`；帳戶憑證留在 CLI。`--profile` 指定對應 context，Vultr 使用 CLI
config file path；Azure 以 `--subscription` 明確指定 subscription，不修改
CLI 的全域預設。`vps quote` 查即時方案；`vps create` 先產生預覽，再用
`--yes --expect` 套用。Oracle 的免費條件仍可能受到用量回報延遲及日後使用量
影響，不是帳單保證。

`vps estimate --egress` 加入預期的 VM 月出網量，沿用供應商顯示的 GB／GiB 單位。
Vultr $5／1024GB 的方案用到 1524GB 時，依此流量費快照估計為 $10。
Linode 顯示 standard／distributed region 費率範圍，不把未知 region 費率當成精確
帳單；Oracle 未經免費資格審核前保持總費用未知。試算不會建立任何雲端資源。

Azure／EC2 的 `monthly_usd` 是 compute＋必要 disk＋固定 IPv4 的合計，
`components` 提供各項價格和來源；stop 預覽另列停止後仍需支付的固定費用。
Azure／EC2 不會把帳戶共用免費流量、trial credits、Savings Plans／Reserved
優惠自動當成這台 VM 的折扣。Lightsail 請另傳 `--ingress`；只有出網量時保留
範圍或未知結果，不假設入站為零。其 allowance 會扣除 inbound 和 outbound，
但超額收費針對 outbound；代理進出雙向都會消耗 allowance。

成本不能只看機器月租：Azure／EC2 的大量出網費可能高於 VM 本身，請以所選
region 的 quote／estimate 和實際用量比較。託管 image 的 Fly.io 能提供 TCP／UDP，但 dedicated
IPv4 $2／月、亞太 outbound $0.04/GB，500GB 就有 $20 流量費。Compose 是安裝
方式，不等於已整合 Fly／Cloud Run；託管容器 adapter 留待後續。

來源：[Oracle](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)、
[RackNerd](https://www.racknerd.com/specials/)、[Vultr plans](https://api.vultr.com/v2/plans)、
[Vultr 流量](https://docs.vultr.com/support/platform/billing/what-is-the-bandwidth-overage-rate)、
[Linode](https://www.akamai.com/cloud/pricing)、[DigitalOcean](https://www.digitalocean.com/pricing/droplets)、
[DO bandwidth](https://docs.digitalocean.com/platform/billing/bandwidth/)、
[Azure](https://azure.microsoft.com/en-us/pricing/details/bandwidth/)、
[Lightsail](https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-faq-data-transfer-allowance.html)、
[Fly.io](https://fly.io/docs/about/pricing/)。

## Azure、AWS Lightsail 與 EC2

以下命令都是唯讀查詢或建立預覽。執行前登入 Azure CLI／設定 AWS profile。

```sh
lazyclash vps discover --provider azure --kind subscriptions --json
lazyclash vps discover --provider azure --subscription SUBSCRIPTION_ID --kind regions --json
lazyclash vps discover --provider aws-ec2 --profile personal --kind regions --json
lazyclash vps discover --provider aws-lightsail --profile personal --region ap-northeast-1 --kind plans --json

lazyclash vps create azure-jp --provider azure --subscription SUBSCRIPTION_ID \
  --region japaneast --architecture auto --ssh-key ~/.ssh/id_ed25519.pub --json
lazyclash vps create lightsail-jp --provider aws-lightsail --profile personal \
  --region ap-northeast-1 --ssh-key ~/.ssh/id_ed25519.pub --json
lazyclash vps create ec2-jp --provider aws-ec2 --profile personal \
  --region ap-northeast-1 --architecture auto --ssh-key ~/.ssh/id_ed25519.pub --json

# 使用 discovery 回傳的實際 bundle ID；單位以 quote 輸出為準。
lazyclash vps estimate --provider aws-lightsail --profile personal \
  --region ap-northeast-1 --plan BUNDLE_ID --egress 500 --ingress 500 --json
```

檢查預覽中的帳戶、region、AZ、固定映像、完整費用與 SSH CIDR。建立時使用
相同參數加 `--yes --expect REVIEWED_DIGEST`；若可用性或報價改變，重新預覽。
`vps create --interactive` 和 TUI 的 **Deploy → Create a cloud VPS** 提供同一
套選擇與 review。非互動命令省略 `--plan` 時，在所選 region 中解析至少 1GiB
RAM 的低成本相容方案；`--architecture auto` 同時允許 ARM 與 x86，不保證
任何型號有容量。ARM／x86 映像必須配對，preview 固定 Ubuntu 24.04 的版本／ID。
Lightsail 首版只使用已核實的 Ubuntu 24.04 x86 blueprint；Azure／EC2 可選 ARM。
可用 `--availability-zone` 固定 AZ；`--disk-gb` 僅供 Azure／EC2 調整根磁碟。

`vps catalog` 也提供美東區域的固定費用快照供比較：Lightsail 1GiB IPv4 bundle
約 $7／月、EC2 T4g micro 加 20GiB gp3 與 IPv4 約 $11.38／月、Azure B2pts v2
加 32GiB Standard SSD 與 IPv4 約 $12.18／月。這些是 730 小時月份的起點，
不含流量、稅與 Azure 磁碟交易費；不同區域以即時 quote 為準。
[Lightsail 價格](https://aws.amazon.com/lightsail/pricing/)、
[EC2 On-Demand](https://aws.amazon.com/ec2/pricing/on-demand/)、
[Azure Retail Prices API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices)。

| Provider | 建立的必要資源 | `vps stop` 的行為 |
|---|---|---|
| `azure` | 專用 resource group、VNet/subnet、NSG、NIC、Standard Static IPv4；預設 32GiB Standard SSD | deallocate VM；保留 disk／IPv4 費用 |
| `aws-lightsail` | Linux IPv4 bundle、獨立 static IP、instance firewall；user-data 安裝 SSH 公鑰 | 停止 instance；bundle 月費仍計收 |
| `aws-ec2` | 專用 VPC/subnet、IGW、route table、SG、EIP、key pair；預設 20GiB encrypted gp3、IMDSv2、Standard CPU credits | 停止 instance；保留 EBS／EIP 費用 |

Azure B-series 與 EC2 T-series 的 CPU burst／credits 限制會顯示於預覽；規格小
不代表可長期跑滿 CPU。這三個 provider 都使用 SSH 公鑰檔，Lightsail 的
user-data 路徑支援 Ed25519。新建流程不建立 NAT Gateway／IAM role，不接管
既有 VPC 或 resource group；既有 VM 仍透過 `vps register` 走 SSH 部署。
首版支援 Azure 商用雲與 AWS commercial partition。

帳戶綁定 Azure cloud＋tenant＋subscription，或 AWS partition＋account。
跨步驟帳戶切換會阻止 apply／resume。EC2 固定 launch request、client token
和 AZ；建立結果不明先 reconcile，不能改 token／AZ 當成同一操作重試。
Lightsail static IP 無 tags 支援，清理使用保存的 ARN／建立時間 receipt 核對。
只刪除可證明由該操作建立的資源；刪除部分失敗保留 inventory 及殘留費用資訊。

費用與停止行為來源：[Azure VM 計費狀態](https://learn.microsoft.com/en-us/azure/virtual-machines/states-billing)、
[Lightsail 計費](https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-frequently-asked-questions-faq-billing-and-account-management.html)、
[EC2 stop/start](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/how-ec2-instance-stop-start-works.html)。

這些 provider 以 mock CLI、唯讀查詢與隔離 PTY 驗證；付費真機建立、刪除與
各 region 網路品質需使用指定帳戶及預算另行驗證。

## 管理、恢復與分享

```sh
lazyclash servers status home-reality --json
lazyclash servers stop home-reality --json
lazyclash servers stop home-reality --yes --expect REVIEWED_DIGEST
lazyclash servers resume home-reality --json

lazyclash servers export home-reality --format uri
lazyclash servers export home-reality --format qr --output /absolute/private/node.png
lazyclash servers export home-reality --format starter --output /absolute/private/client.yaml
lazyclash servers export home-reality --format admin-bundle --output /absolute/private/server.json

lazyclash --target desktop servers connect home-reality --group PROXY --json
# 檢查 client source diff 後，以相同參數加 --yes --expect DIGEST。
```

一般分享包含 client 所需憑證，不含服務端私鑰。管理備份是明確的私人匯出，包含
server configuration、artifact references、ownership token，以及已簽發的 TLS
憑證／私鑰；排除雲端登入憑證與 SSH 私鑰。檔案使用 0600 且不覆寫既有檔案。
Verge 匯入後仍需原生重新啟用 profile；未知匯入結果先 verify，不重複新增節點。

主機建立前先保存操作意圖；雲端回應後立即保存資源 ID，SSH 尚未可達也保留主機。
遇到建立結果不明，`vps resume ID` 按同一帳戶與操作標記查明，不盲目建立第二台。
只需找回已存在的資源、準備清理時，使用 `vps resume ID --reconcile-only`；這個
路徑只保存找到的資源，不建立或掛接任何雲端資源。
Resume 同樣先預覽，再以 `--yes --expect` 套用；只允許尚未送出 VM 建立要求的
原操作繼續準備資源，已送出的不確定建立只做查明。
服務端另有分階段 checkpoint，重新執行時保留 UUID／密鑰／憑證與已完成的步驟。

`servers stop/remove` 操作代理服務；`vps stop/delete` 操作雲端資源。
VM 關機通常仍收費；BYO SSH 主機沒有 provider 電源 API，不能在關機後用 SSH 開機。
刪除雲端 VM 須先移除其 managed server，只清理由本次流程持有的資源。

狀態分開呈現 SSH、服務程序、上次代理驗證及出口 IP。驗證使用臨時 Mihomo
進行真實 HTTPS 請求，不改動既有 client；代理失敗不改走直連。
出口 IP 可能不同於入站 IP。公開位址變更會標記 client 配置需要更新。
只改公開端點時仍可檢查、停止和移除已知服務；SSH／provider／resource identity
改變需要重新審查部署。既有分享連結不會被默默改寫。

`servers.toml` 預設在主設定檔旁，可用 `--servers-config` 或
`LAZYCLASH_SERVERS_CONFIG` 指定。私密日誌在 `$XDG_STATE_HOME/lazyclash/servers/`
下按 inventory 路徑隔離。唯讀列表、補全與預覽不建立記錄，TOML 更新保留註解與
未知欄位並偵測外部修改。備份時同時保存 inventory 和私人 state。
