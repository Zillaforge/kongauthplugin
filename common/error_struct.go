package common

import "encoding/json"

type ErrorStruct struct {
	Message string `json:"message"`
}

func NewErrorStruct(message string) ErrorStruct {
	return ErrorStruct{
		Message: message,
	}
}

func (e ErrorStruct) ToBytes() (b []byte) {
	b, _ = json.Marshal(e)
	return
}
