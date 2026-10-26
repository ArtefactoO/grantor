package connector

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

const SnapshotGzipV1 = "gzip-v1"
const MaxDecodedSnapshotBytes = 128 << 20
const maxCompressedSnapshotBytes = 23 << 20

type encodedDiscoveryResult struct {
	Encoding string `json:"snapshot_encoding"`
	Data     []byte `json:"data"`
}

func MarshalDiscoveryResult(snapshot *adapter.Snapshot, encoding string) (json.RawMessage, error) {
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxDecodedSnapshotBytes {
		return nil, fmt.Errorf("connector: discovery snapshot exceeds decoded size limit")
	}
	if encoding == "" {
		return raw, nil
	}
	if encoding != SnapshotGzipV1 {
		return nil, fmt.Errorf("connector: unsupported snapshot encoding")
	}
	var compressed bytes.Buffer
	w, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if compressed.Len() > maxCompressedSnapshotBytes {
		return nil, fmt.Errorf("connector: compressed snapshot exceeds frame budget")
	}
	return json.Marshal(encodedDiscoveryResult{Encoding: encoding, Data: compressed.Bytes()})
}

func decodeDiscoveryGzip(data []byte, limit int64) ([]byte, error) {
	if len(data) > maxCompressedSnapshotBytes {
		return nil, fmt.Errorf("connector: oversized compressed snapshot")
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close() //nolint:errcheck
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("connector: discovery snapshot exceeds decoded size limit")
	}
	return raw, nil
}

func ParseDiscoveryResult(raw json.RawMessage) (*adapter.Snapshot, error) {
	if len(raw) > MaxDecodedSnapshotBytes {
		return nil, fmt.Errorf("connector: oversized discovery result")
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil || document == nil {
		return nil, fmt.Errorf("connector: invalid discovery result")
	}
	if _, encoded := document["snapshot_encoding"]; encoded {
		var envelope encodedDiscoveryResult
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&envelope) != nil || envelope.Encoding != SnapshotGzipV1 {
			return nil, fmt.Errorf("connector: unsupported discovery result envelope")
		}
		decoded, err := decodeDiscoveryGzip(envelope.Data, MaxDecodedSnapshotBytes)
		if err != nil {
			return nil, err
		}
		raw = decoded
		if err := json.Unmarshal(raw, &document); err != nil || document == nil {
			return nil, fmt.Errorf("connector: invalid decoded snapshot")
		}
	}
	if _, ok := document["Resources"]; !ok {
		return nil, fmt.Errorf("connector: discovery result does not contain snapshot resources")
	}
	if _, ok := document["Accounts"]; !ok {
		return nil, fmt.Errorf("connector: discovery result does not contain snapshot accounts")
	}
	var snapshot adapter.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}
