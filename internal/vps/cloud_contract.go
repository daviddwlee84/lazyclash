package vps

import (
	"context"
	"errors"

	"github.com/daviddwlee84/lazyclash/internal/serverstate"
)

// New cloud adapters own their complete resource graph. Legacy providers retain
// their existing workflow. Resolve/Discover/Identity/Observe/ValidateAction never
// write to a provider. Provision(false) only reconciles already submitted work.
type cloudAdapter interface {
	Resolve(context.Context, CreateRequest) (CreateRequest, Quote, error)
	Discover(context.Context, CreateRequest, string) ([]Choice, error)
	Identity(context.Context, CreateRequest) (string, error)
	Provision(context.Context, *operation, bool) error
	Observe(context.Context, operation) (serverstate.Host, error)
	ValidateAction(context.Context, operation, string) error
	Action(context.Context, *operation, string) error
}

type cloudResource struct {
	Kind    string            `json:"kind"`
	ID      string            `json:"id"`
	Name    string            `json:"name,omitempty"`
	Proof   map[string]string `json:"proof,omitempty"`
	Deleted bool              `json:"deleted,omitempty"`
}

func cloudResourceOf(op *operation, kind string) *cloudResource {
	for i := range op.CloudResources {
		if op.CloudResources[i].Kind == kind {
			return &op.CloudResources[i]
		}
	}
	return nil
}

func (s *Service) cloudPersist(op *operation) error {
	for _, receipt := range op.CloudResources {
		if receipt.Deleted {
			kept := op.Host.Resources[:0]
			for _, resource := range op.Host.Resources {
				if resource.Kind != receipt.Kind || resource.ID != receipt.ID {
					kept = append(kept, resource)
				}
			}
			op.Host.Resources = kept
		}
	}
	if err := s.writeOperation(*op); err != nil {
		return err
	}
	return s.saveHost(op.Host)
}

func (s *Service) cloudRecord(op *operation, resource cloudResource) error {
	if old := cloudResourceOf(op, resource.Kind); old != nil {
		if old.ID != resource.ID || (old.Deleted && !resource.Deleted) {
			return errors.New("cloud resource identity cannot be replaced within an operation")
		}
		*old = resource
	} else {
		op.CloudResources = append(op.CloudResources, resource)
	}
	if !resource.Deleted {
		addFirewallResource(&op.Host, resource.Kind, resource.ID, true)
	}
	if op.PendingResourceKind == resource.Kind {
		op.PendingResourceKind = ""
	}
	return s.cloudPersist(op)
}
