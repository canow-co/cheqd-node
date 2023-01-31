package types

import "github.com/canow-co/cheqd-node/x/did/utils"

func NormalizeVerificationMethod(vm *VerificationMethod) {
	vm.Controller = utils.NormalizeDID(vm.Controller)
	vm.Id = utils.NormalizeDIDUrl(vm.Id)
}

func NormalizeService(s *Service) {
	s.Id = utils.NormalizeDIDUrl(s.Id)
}

func NormalizeVerificationRelationshipList(vrs []*VerificationRelationship) {
	for i := range vrs {
		if vrs[i].VerificationMethod != nil {
			NormalizeVerificationMethod(vrs[i].VerificationMethod)
		} else {
			vrs[i].VerificationMethodId = utils.NormalizeDIDUrl(vrs[i].VerificationMethodId)
		}
	}
}
