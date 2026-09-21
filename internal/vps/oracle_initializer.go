package vps

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// OCI's official Ubuntu setup requires both VCN ingress and host iptables:
// https://docs.oracle.com/en-us/iaas/Content/developer/apache-on-ubuntu/01oci-ubuntu-apache-summary.htm
// This initializer is fixed code sent only in a new instance launch request.
// It is never run against registered hosts or already-created instances.
const oracleInitializerVersion = "oci-ubuntu-ingress-v1"

//go:embed assets/oracle-cloud-init.yaml
var oracleCloudInit []byte

func oracleInitializerSHA256() string {
	sum := sha256.Sum256(oracleCloudInit)
	return hex.EncodeToString(sum[:])
}

func validateOracleInitializer(req CreateRequest) error {
	if req.InitializerVersion != oracleInitializerVersion || req.InitializerSHA256 != oracleInitializerSHA256() {
		return fmt.Errorf("Oracle initializer differs from the reviewed version/hash; no VM was launched; use the reviewed lazyclash version or remove the partial resources and create a fresh plan")
	}
	return nil
}

func oracleLaunchMetadata(req CreateRequest, publicKey string) (map[string]string, error) {
	if err := validateOracleInitializer(req); err != nil {
		return nil, err
	}
	return map[string]string{"ssh_authorized_keys": publicKey, "user_data": base64.StdEncoding.EncodeToString(oracleCloudInit)}, nil
}
