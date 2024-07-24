package util

import (
	"bytes"
	"encoding/json"

	"github.com/pkg/errors"
)

func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	je := json.NewEncoder(&buf)
	je.SetEscapeHTML(false)
	if err := je.Encode(v); err != nil {
		return nil, errors.Wrap(err, "json encode")
	}
	return buf.Bytes(), nil
}

func Unmarshal(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return errors.Wrap(err, "json unmarshal")
	}
	return nil
}
