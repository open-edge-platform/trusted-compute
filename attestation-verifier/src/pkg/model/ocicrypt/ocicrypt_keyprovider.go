package ocicrypt_keyprovider

type AnnotationPacket struct {
	KeyUrl     string `json:"key_url"`
	WrappedKey []byte `json:"wrapped_key"`
	WrapType   string `json:"wrap_type"`
}

type AesPacket struct {
	Ciphertext []byte `json:"cipher_text"`
	Nonce      []byte `json:"nonce"`
}
