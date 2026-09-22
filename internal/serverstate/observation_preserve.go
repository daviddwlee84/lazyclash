package serverstate

import (
	"github.com/pelletier/go-toml/v2/unstable"
)

func patchObservation(raw []byte, scope string, binding *CloudObservationBinding) ([]byte, error) {
	exprs, err := expressions(raw)
	if err != nil {
		return nil, err
	}
	from, to := -1, len(raw)
	for _, e := range exprs {
		if e.kind != unstable.Table && e.kind != unstable.ArrayTable {
			continue
		}
		if from >= 0 {
			to = e.start
			break
		}
		if e.key == scope {
			from = e.start
		}
	}
	if binding == nil {
		if from >= 0 {
			return applyEdits(raw, []edit{{from: from, to: to}}), nil
		}
		return raw, nil
	}
	section := []byte("[" + scope + "]\n")
	if from >= 0 {
		section = raw[from:to]
	}
	section, err = patchFields(section, scope, fields(*binding))
	if err != nil {
		return nil, err
	}
	if from < 0 {
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			raw = append(raw, '\n')
		}
		return append(raw, section...), nil
	}
	return applyEdits(raw, []edit{{from: from, to: to, data: section}}), nil
}
