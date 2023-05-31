package oi4vp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPresentationDefinition(t *testing.T) {
	pd := &PresentationDefinition{
		ID: "alternative credentials",
		InputDescriptors: []InputDescriptor{
			{
				ID: "id card credential",
				Format: map[string]any{
					"ldp_vc": map[string]any{
						"proof_type": []string{"Ed25519Signature2018"},
					},
				},
			},
		},
	}

	_, err := pd.String()
	if err != nil {
		t.Fatal(err)
	}
}

func TestPresentationDefinitionFromURI(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"alternative credentials","submission_requirements":[{"name":"Citizenship Information","rule":"pick","count":1,"from":"A"}],"input_descriptors":[{"id":"id card credential","group":["A"],"format":{"ldp_vc":{"proof_type":["Ed25519Signature2018"]}},"constraints":{"fields":[{"path":["$.type"],"filter":{"type":"string","pattern":"IDCardCredential"}}]}},{"id":"passport credential","format":{"jwt_vc_json":{"alg":["RS256"]}},"group":["A"],"constraints":{"fields":[{"path":["$.vc.type"],"filter":{"type":"string","pattern":"PassportCredential"}}]}}]}`)
	}))

	defer ts.Close()

	pd, _ := PresentationDefinitionFromURI(ts.URL)

	assert.Equal(t, "alternative credentials", pd.ID)
	assert.Equal(t, "Citizenship Information", pd.SubmissionRequirements[0].Name)
	assert.Equal(t, "id card credential", pd.InputDescriptors[0].ID)
	assert.Equal(t, "IDCardCredential", pd.InputDescriptors[0].Constraints.Fields[0].Filter.Pattern)
	assert.Equal(t, "passport credential", pd.InputDescriptors[1].ID)
}

func TestPresentationSubmission(t *testing.T) {
	data := `{"id":"Presentation example 2","definition_id":"Example with multiple VPs","descriptor_map":[{"id":"ID Card with constraints","format":"ldp_vp","path":"$[0]","path_nested":{"format":"ldp_vc","path":"$[0].verifiableCredential[0]"}},{"id":"Ontario Health Insurance Plan","format":"jwt_vp_json","path":"$[1]","path_nested":{"format":"jwt_vc_json","path":"$[1].vp.verifiableCredential[0]"}}]}`
	ps, _ := PresentationSubmissionFromString(data)

	assert.Equal(t, "Presentation example 2", ps.ID)
	assert.Equal(t, "Example with multiple VPs", ps.DefinitionID)
	assert.Equal(t, "ID Card with constraints", ps.DescriptorMap[0].ID)
	assert.Equal(t, "$[0].verifiableCredential[0]", ps.DescriptorMap[0].PathNested.Path)
	assert.Equal(t, "Ontario Health Insurance Plan", ps.DescriptorMap[1].ID)
}
