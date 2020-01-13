package utils

import "strconv"

type StringMap map[string]interface{}

func (sm StringMap) GetString(key string) string {
	val, ok := sm[key]
	if ok {
		if vl, ok := val.(string); ok {
			return vl
		}
	}
	return ""
}

func (sm StringMap) ToStruct(data interface{}) error {
	dataStr := ToJson(sm)
	return FromJson(dataStr, data)
}

func (sm StringMap) GetBool(key string) bool {
	val, ok := sm[key]
	if ok {
		if vl, ok := val.(bool); ok {
			return vl
		}
	}
	return false
}

func (sm StringMap) GetArray(key string) []StringMap {
	val, ok := sm[key]
	if ok {
		if vl, ok := val.([]StringMap); ok {
			return vl
		}
	}
	return nil
}

func (sm StringMap) GetInt64(key string) int64 {
	val, ok := sm[key]
	if ok {
		if vl, ok := val.(int64); ok {
			return vl
		}
		if vl, ok := val.(string); ok {
			i, err := strconv.ParseInt(vl, 10, 64)
			if err == nil {
				return i
			}
		}
	}
	return 0
}

func (sm StringMap) Add(key string, value interface{}) {
	if len(key) > 0 {
		sm[key] = value
	}
}

type Requirements struct {
	Password *PasswordString `yaml:"password,omitempty" json:"password,omitempty"`
	Labels   StringMap          `yaml:"labels,omitempty" json:"labels,omitempty"`
}

func (r Requirements) String() string {
	p := r.Password
	if p != nil {
		pm := PasswordString("***")
		r.Password = &pm
	}
	return ToJson(r)
}
