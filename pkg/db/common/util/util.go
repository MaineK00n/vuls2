package util

import (
	"bytes"
	"encoding/json"

	"github.com/klauspost/compress/zstd"
	"github.com/pkg/errors"
)

func Marshal(v any, compress bool) ([]byte, error) {
	var buf bytes.Buffer
	je := json.NewEncoder(&buf)
	je.SetEscapeHTML(false)
	if err := je.Encode(v); err != nil {
		return nil, errors.Wrap(err, "json encode")
	}

	if compress {
		zw, err := zstd.NewWriter(nil)
		if err != nil {
			return nil, errors.Wrap(err, "new zstd writer")
		}
		return zw.EncodeAll(buf.Bytes(), make([]byte, 0, buf.Len())), nil
	}
	return buf.Bytes(), nil
}

func Unmarshal(data []byte, compress bool, v any) error {
	if compress {
		zr, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return errors.Wrap(err, "new zstd reader")
		}
		defer zr.Close()

		if err := json.NewDecoder(zr).Decode(v); err != nil {
			return errors.Wrap(err, "json decode")
		}

		return nil
	}

	if err := json.Unmarshal(data, v); err != nil {
		return errors.Wrap(err, "json unmarshal")
	}

	return nil
}
