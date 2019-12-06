package utils

type StringMap map[string]interface{}

type Requirements struct {
	Password *PasswordString `yaml:"password,omitempty" json:"password,omitempty"`
	Labels   Labels          `yaml:"labels,omitempty" json:"labels,omitempty"`
}

func (r Requirements) String() string {
	p := r.Password
	if p != nil {
		pm := PasswordString("***")
		r.Password = &pm
	}
	return ToJson(r)
}
