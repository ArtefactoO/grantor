// Классическое OpenPGP-шифрование секрета для Yopass. Свежая библиотека
// jhaals/yopass шифрует с AEAD (SEIPDv2, GCM) — этот формат не умеют
// расшифровывать web-клиенты старых инсталляций Yopass (openpgp.js без
// поддержки AEAD молча падает как «Invalid password» при верном ключе).
// Общий инстанс организации — как раз такая инсталляция, поэтому шифруем
// сами в классическом формате SEIPDv1+MDC (AES-256, iterated S2K): его
// читают и старые, и новые клиенты. Ключ и plaintext в ошибки не попадают.
package yopass

import (
	"bytes"
	pgpcrypto "crypto"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// classicPGPConfig — параметры шифрования без AEAD: SEIPDv1 + MDC.
// Совместимо с openpgp.js любых поколений.
var classicPGPConfig = &packet.Config{
	DefaultHash:            pgpcrypto.SHA256,
	DefaultCipher:          packet.CipherAES256,
	DefaultCompressionAlgo: packet.CompressionNone,
}

// encryptClassic симметрично шифрует message ключом key и возвращает
// armored PGP message ("PGP MESSAGE"), как ожидает Yopass API.
func encryptClassic(message []byte, key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("yopass: encrypt: key is empty")
	}
	buf := new(bytes.Buffer)
	armorer, err := armor.Encode(buf, "PGP MESSAGE", nil)
	if err != nil {
		return "", fmt.Errorf("yopass: encrypt: create armor encoder: %w", err)
	}
	w, err := openpgp.SymmetricallyEncrypt(armorer, []byte(key), nil, classicPGPConfig)
	if err != nil {
		return "", fmt.Errorf("yopass: encrypt: %w", err)
	}
	if _, err := io.Copy(w, bytes.NewReader(message)); err != nil {
		return "", fmt.Errorf("yopass: encrypt: write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("yopass: encrypt: close writer: %w", err)
	}
	if err := armorer.Close(); err != nil {
		return "", fmt.Errorf("yopass: encrypt: close armor: %w", err)
	}
	return buf.String(), nil
}
