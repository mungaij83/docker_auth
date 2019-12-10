package utils

type StringMap map[string]interface{}

func (sm StringMap) GetString(key string) string {
	val, ok := sm[key]
	if ok {
		return val.(string)
	}
	return ""
}

func (sm StringMap) Add(key string, value interface{}) {
	if len(key) > 0 {
		sm[key] = value
	}
}

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
