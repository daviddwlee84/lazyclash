# VPS 每人／每裝置憑證與生命週期管理

**Status**: P?
**Effort**: L
**Related**: `TODO.md` · server deployment/export · historical analytics

## Context

2026-09-22：歷史流量分析需要辨識來源。現有 deployment 產生單一 UUID／密碼，
多人共用時，來源 IP 是網路端點而非可靠的人或裝置身分。第一版 analytics 沿用
目前憑證，顯示觀測來源和未知歸因；憑證管理另外實作，避免分析安裝偷偷換掉帳號。

## Investigation

- VLESS／VMess 支援同 inbound 多個使用者：UUID 是憑證，`email` 是伺服器端
  識別／統計標籤，不必是真實信箱。以部署版本確認 `clients`／`users` 相容格式。
- Xray `HandlerService.AlterInbound` 的 AddUser／RemoveUser 修改執行中狀態；
  沒有自動寫回持久配置的契約，不能只呼叫 API 就宣稱撤銷在重啟後仍有效。
- 原始碼中 RemoveUser 移除認證資料，不能據此保證已認證的長連線或 multiplex
  transport 立即停止。若以重啟確保失效，須顯示同服務其他使用者也會中斷。
- VLESS／VMess 的非空 email 不可重複，查找不區分大小寫。新舊 UUID 重疊輪替
  需不同 credential labels，再映射至同一穩定 person/device ID。
- Hysteria2 有多使用者認證與按 ID kick API；kick 必須配合拒絕重新認證。
  其撤銷契約不同，不能直接套用 Xray 實作。

## Decision

先規劃持久設定為準的版本：registry 是 users 清單的唯一擁有者，生成 server
配置及指定裝置 client profile。保留舊憑證為明確 legacy entry。新增、撤銷、
輪替皆經驗證、差異預覽、套用與讀回；新增憑證不進一般日誌／analytics 報表。

動態 API 更新列後續，須先解決持久化、重啟 reconciliation 和未知寫入結果。
提供穩定裝置 ID、獨立隨機 UUID、版本化 credential ID；不把來源 IP 當成 owner。

## Acceptance and remaining decisions

- A／B 可獨立發放、匯出及統計；撤銷 A 後新認證失敗，B 正常。
- 分別驗證新握手、已建立 TCP、UDP、multiplex 的撤銷行為。
- 輪替後新憑證成功、舊憑證失敗；重啟與重新生成配置不復活已撤銷憑證。
- 套用失敗與不確定結果保留恢復資料；原始憑證不出現在摘要、診斷或一般 JSON。
- 實作前決定第一版是否支援重疊輪替，以及哪些 core 版本可免重啟更新。

## References

- [VLESS inbound](https://xtls.github.io/en/config/inbounds/vless.html)
- [VMess inbound](https://xtls.github.io/en/config/inbounds/vmess.html)
- [Xray Stats](https://xtls.github.io/en/config/stats.html)
- [Xray API](https://xtls.github.io/en/config/api.html)
- [HandlerService implementation](https://github.com/XTLS/Xray-core/blob/main/app/proxyman/command/command.go)
- [VLESS validator](https://github.com/XTLS/Xray-core/blob/main/proxy/vless/validator.go)
- [Hysteria2 traffic statistics](https://v2.hysteria.network/docs/advanced/Traffic-Stats-API/)
