# fsblob [![Go Report Card](https://goreportcard.com/badge/github.com/smitajit/fsblob)](https://goreportcard.com/report/github.com/smitajit/fsblob)[![Go Reference](https://pkg.go.dev/badge/github.com/smitajit/fsblob.svg)](https://pkg.go.dev/github.com/smitajit/fsblob)
File System based blob store with encryption,metadata and integrity check support

## Features
### Reader and Writer
Blob provides io.Reader and io.Writer interfaces to read and write binary data
```go
	w, err := blob.Writer()
	if err != nil {
		log.Fatal(err)
	}

	r, err := blob.Reader()
	if err != nil {
		log.Fatal(err)
	}
```
### Metadata
Blob provides APIs to store and retrieve metadata of the blob
``` go
	if err := blob.Put("key", "value"); err != nil {
		log.Fatal(err)
	}

	if v, err := blob.Get("key"); err != nil || v != "value" {
		log.Fatal("value not found")
	}

	if err := blob.PutAll(map[string]string{
		"key-1": "value-1",
		"key-2": "value-2",
	}); err != nil {
		log.Fatal(err)
	}

	m, err :=  blob.GetAll() 
	if err != nil {
		log.Fatal(err)
	}
```
### Encryption (dual key encryption)
Blob content along with metadata can be encrypted by providing a primary encryption key.
For each blob a random secondary encryption (aes256 bit) key is created to encrypt the blob content.
Secondary encryption key along with the metadata is encrypted with the primary cipher.
```go
	key := make([]byte, 32)
	if _, err := crand.Read(key); err != nil {
		log.Fatal(err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}

	bucket, err := fsblob.NewBucket(path, aead)
	if err != nil {
		log.Fatal(err)
	}
```
### Integrity
Blobs can be sealed and verified. Once sealed, a HMAC sum of the blob content is calculated and stored in the metadata.
Upon verification, the sum is verified against the blob content.
``` go

	// seal the blob
	if err := blob.Seal(); err != nil {
		log.Fatal(err)
	}

	// verify the glob
	if err := blob.Verify(); err != nil {
		log.Fatal("blob integrity compromised. error: %v", err)
	}
```
