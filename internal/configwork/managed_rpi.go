package configwork

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/daviddwlee84/lazyclash/internal/config"
	"github.com/daviddwlee84/lazyclash/internal/managedrpi"
)

func applyManaged(ctx context.Context, t config.Target, p Plan, o Options) (Receipt, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Receipt{}, err
	}
	now := time.Now().UTC()
	r := Receipt{ID: hex.EncodeToString(id[:]), TargetID: t.ID, Binding: Binding(t), Owner: managedrpi.Kind, Kind: p.Kind, Name: p.Name, Status: "prepared", Changes: p.Changes, CreatedAt: now, UpdatedAt: now, BrokerReceipt: p.brokerReceipt}
	if r.BrokerReceipt == "" {
		return r, errors.New("managed RPi preview has no owner receipt")
	}
	if _, err := receiptDir(o, r.ID, true); err != nil {
		return r, err
	}
	if err := saveReceipt(o, r); err != nil {
		return r, err
	}
	return managedReceipt(ctx, t, r, "apply", o)
}
func managedReceipt(ctx context.Context, t config.Target, r Receipt, operation string, o Options) (Receipt, error) {
	if t.ManagedRPi == nil || r.BrokerReceipt == "" {
		return r, errors.New("managed RPi receipt is missing its owner binding")
	}
	if operation != "verify" && o.ReadOnly {
		return r, errors.New("managed RPi changes are disabled in read-only mode")
	}
	out, err := managedrpi.Call(ctx, t, managedrpi.Request{Operation: operation, ReceiptPath: r.BrokerReceipt}, o.Broker)
	r.UpdatedAt = time.Now().UTC()
	r.SourceVerified, r.GeneratedVerified, r.RuntimeObserved = false, false, false
	if err != nil {
		r.Status = "owner_result_unknown"
		r.Message = "RPi-ImmortalWrt 交易結果尚未確認；保留 broker receipt，先 verify，勿自動重試。"
		_ = saveReceipt(o, r)
		return r, err
	}
	r.Status = out.State
	if out.State == "confirmed" {
		r.Status = "source_and_structure_verified"
		r.SourceVerified = true
		r.GeneratedVerified = true
		r.RuntimeObserved = true
	}
	if out.State == "restored" {
		r.Restored = true
		r.SourceVerified = true
		r.GeneratedVerified = true
		r.RuntimeObserved = true
	}
	r.Message = "RPi-ImmortalWrt broker 回報：" + out.State + "。實際流量需另行測試。"
	return r, saveReceipt(o, r)
}
