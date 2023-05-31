package oi4vp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type PresentationDefinition struct {
	ID                     string                  `json:"id"`
	InputDescriptors       []InputDescriptor       `json:"input_descriptors"`
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements,omitempty"`
}

func (pd *PresentationDefinition) String() (string, error) {
	if pd.ID == "" {
		return "", fmt.Errorf("presentation definition ID is required")
	}

	if pd.InputDescriptors == nil {
		return "", fmt.Errorf("presentation definition input descriptors are required")
	}

	data, _ := json.Marshal(pd)
	return string(data), nil
}

func PresentationDefinitionFromURI(uri string) (*PresentationDefinition, error) {
	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	pd := &PresentationDefinition{}
	err = json.Unmarshal(body, &pd)
	if err != nil {
		return nil, err
	}

	return pd, nil
}

func PresentationDefinitionFromScope(scope string) (*PresentationDefinition, error) {
	return nil, fmt.Errorf("not implemented")
}

type InputDescriptor struct {
	ID          string         `json:"id"`
	Group       []string       `json:"group,omitempty"`
	Format      map[string]any `json:"format,omitempty"`
	Name        string         `json:"name,omitempty"`
	Purpose     string         `json:"purpose,omitempty"`
	Constraints Constraint     `json:"constraints,omitempty"`
}

type Constraint struct {
	Fields          []Field `json:"fields,omitempty"`
	LimitDisclosure bool    `json:"limit_disclosure,omitempty"`
}

type Field struct {
	Path     []string `json:"path"`
	Filter   Filter   `json:"filter"`
	ID       string   `json:"id"`
	Purpose  string   `json:"purpose"`
	Name     string   `json:"name"`
	Optional bool     `json:"optional"`
}

type Filter struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
}

type SubmissionRequirement struct {
	Name       string                 `json:"name"`
	Purpose    string                 `json:"purpose"`
	Rule       string                 `json:"rule"`
	Count      int                    `json:"count"`
	From       string                 `json:"from"`
	FromNested *SubmissionRequirement `json:"from_nested"`
}

type PresentationSubmission struct {
	ID            string          `json:"id"`
	DefinitionID  string          `json:"definition_id"`
	DescriptorMap []DescriptorMap `json:"descriptor_map"`
}

func PresentationSubmissionFromString(data string) (*PresentationSubmission, error) {
	ps := &PresentationSubmission{}
	err := json.Unmarshal([]byte(data), &ps)
	if err != nil {
		return nil, err
	}

	if ps.ID == "" {
		return nil, fmt.Errorf("presentation submission ID is required")
	}

	if  ps.DefinitionID == "" {
		return nil, fmt.Errorf("presentation submission definition ID is required")
	}

	if ps.DescriptorMap == nil {
		return nil, fmt.Errorf("presentation submission descriptor map is required")
	}

	return ps, nil
}

type DescriptorMap struct {
	ID         string     `json:"id"`
	Path       string     `json:"path"`
	Format     string     `json:"format"`
	PathNested PathNested `json:"path_nested"`
}

type PathNested struct {
	Path       string      `json:"path"`
	Format     string      `json:"format"`
	PathNested *PathNested `json:"path_nested"`
}
