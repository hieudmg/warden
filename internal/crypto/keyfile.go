package crypto

const masterKeySize = 32

func LoadMasterKey(path string) ([masterKeySize]byte, error) {
	return loadMasterKeyPlatform(path)
}
