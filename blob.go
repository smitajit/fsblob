package fsblob

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type (
	// Bucket represents a collection os blobs and sub buckets
	Bucket struct {
		path   string // bucket path path
		cipher cipher.AEAD
	}

	// Blob represents a blob which is available to read/write/get/put binary data
	Blob interface {
		// ID returns the id of the blob
		ID() string
		// Reader return a reader to read the blob
		Reader() (io.Reader, error)
		// Writer return a writer to write to the blob
		Writer() (io.Writer, error)
		// Put puts the key value pair in the blob metadata
		Put(k, v string) error
		// Get gets the value for the given key from the blob metadata
		Get(k string) (string, error)
		// PutAll puts the map in the blob metadata
		PutAll(map[string]string) error
		// GetAll gets all the values from blob metadata
		GetAll() (map[string]string, error)
		// Size of the blob. returns 0 if file doesn't exists
		Size() int64
		// Timestamp returns the last modified timestamp of the blob
		Timestamp() (time.Time, error)
		// Seal seals the blob by storing the hash of the content.
		// After the blob is sealed, the blob will become readonly
		Seal() error
		// Verify verifies the blob hash value
		Verify() error
		// Close closes the blob
		Close() error
	}

	// ListBlobsFn is the callback function called by ListBlobsFn to list each blob for the given bucket
	// returning error will cancel the walk
	ListBlobsFn = func(b Blob) error

	// ListBucketsFn is the callback function called by ListBuckets to list each sub bucket for the given bucket
	// returning error will cancel the walk
	ListBucketsFn = func(b *Bucket) error
)

// Blob metadata keys
const (
	KeySignature  = "_signature"
	KeyEncryption = "_encryption"
)

// DefaultFilePerm is the default file permissions of recoding dirs and files.
const DefaultFilePerm = 0700

// Errors
var (
	ErrNotFound    = errors.New("blob: not found")
	ErrSigNotFound = errors.New("blob: signature not found")
	ErrSigMisMatch = errors.New("blob: signature mismatch")
	ErrSealed      = errors.New("blob: sealed")
)

var (
	fileExtBlob    = ".blob"
	fileExtMeta    = ".meta"
	weakHashSecret = []byte("weak-hash-secret")
)

// NewBucket creates a new Bucket for the given path
// If the cipher is nil the the blobs will not be encrypted
func NewBucket(path string, aead cipher.AEAD) (*Bucket, error) {
	if err := os.MkdirAll(filepath.Clean(path), DefaultFilePerm); err != nil {
		return nil, err
	}

	return &Bucket{path: path, cipher: aead}, nil
}

// New creates new blob in the Bucket
func (b *Bucket) New(id string) (Blob, error) {
	m, err := os.Create(filepath.Join(b.path, id+fileExtMeta))
	if err != nil {
		return nil, err
	}
	defer m.Close()

	blob := &blob{
		f:      filepath.Join(b.path, id+fileExtBlob),
		meta:   m.Name(),
		hasher: newHasher(weakHashSecret),
		sealed: false,
	}
	if b.cipher == nil {
		return blob, nil
	}

	return b.encrypt(blob)
}

// Open opens and existing Blob in the bucket
func (b *Bucket) Open(id string) (Blob, error) {
	m, err := os.Open(filepath.Join(b.path, id+fileExtMeta))
	if err != nil {
		return nil, err
	}
	defer m.Close()

	blob := &blob{
		f:      filepath.Join(b.path, id+fileExtBlob),
		meta:   m.Name(),
		hasher: newHasher(weakHashSecret),
	}
	sig, _ := blob.Get(KeySignature)
	if sig != "" {
		blob.sealed = true
	}

	if b.cipher == nil {
		return blob, nil
	}

	return b.encrypt(blob)
}

// Child creates a new or returns an existing sub bucket in the bucket
func (b *Bucket) Child(id string) (*Bucket, error) {
	path := filepath.Join(b.path, id)
	if err := os.MkdirAll(path, DefaultFilePerm); err != nil {
		return nil, err
	}

	return &Bucket{path: path, cipher: b.cipher}, nil
}

// ID returns the ID of the bucket
func (b *Bucket) ID() string {
	return filepath.Base(b.path)
}

// Path returns path of the bucket
func (b *Bucket) Path() string {
	return b.path
}

// ListBuckets lists the sub buckets of the bucket
func (b *Bucket) ListBuckets(cb ListBucketsFn) error {
	files, err := ioutil.ReadDir(b.path)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.IsDir() {
			bucket, err := NewBucket(filepath.Join(b.path, f.Name()), b.cipher)
			if err != nil {
				return err
			}
			if err = cb(bucket); err != nil {
				return err
			}
		}
	}
	return nil
}

// ListBlobs lists the blobs inside the bucket
func (b *Bucket) ListBlobs(cb ListBlobsFn) error {
	files, err := ioutil.ReadDir(b.path)
	if err != nil {
		return err
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) == fileExtMeta {
			blob, err := b.Open(strings.TrimSuffix(f.Name(), filepath.Ext(f.Name())))
			if err != nil {
				return err
			}

			if err := cb(blob); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *Bucket) encrypt(blob *blob) (*encblob, error) {
	encblob := &encblob{blob: blob, pcipher: b.cipher}

	var key []byte
	if k, err := encblob.Get(KeyEncryption); err == nil {
		key, err = hex.DecodeString(k)
		if err != nil {
			return nil, err
		}
	} else if err != ErrNotFound {
		return nil, err
	} else {
		key = make([]byte, 32)
		if _, err = crand.Read(key); err != nil {
			return nil, err
		}

		if err := encblob.Put(KeyEncryption, hex.EncodeToString(key)); err != nil {
			return nil, err
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encblob.scipher = block
	encblob.blob.hasher = &hasher{secret: key, hash: hmac.New(sha256.New, key)}

	return encblob, nil
}

// encblob represents a encrypted blob
type encblob struct {
	r       *cipher.StreamReader
	w       *cipher.StreamWriter
	blob    *blob
	pcipher cipher.AEAD  // primary cipher to encrypt metadata and secondary encryption key
	scipher cipher.Block // secondary cipher key to encrypt the stream
}

func (b *encblob) ID() string {
	return b.blob.ID()
}

func (b *encblob) Get(k string) (string, error) {
	v, err := b.blob.Get(k)
	if err != nil {
		return "", err
	}

	p, err := decrypt(v, b.pcipher)
	if err != nil {
		return "", err
	}
	return string(p), nil
}

func (b *encblob) Put(k, v string) error {
	p, err := encrypt([]byte(v), b.pcipher)
	if err != nil {
		return err
	}

	return b.blob.Put(k, string(p))
}

func (b *encblob) GetAll() (map[string]string, error) {
	m, err := b.blob.GetAll()
	if err != nil {
		return nil, err
	}
	meta := make(map[string]string)
	for k, v := range m {
		v1, err := decrypt(v, b.pcipher)
		if err != nil {
			return nil, err
		}
		meta[k] = string(v1)
	}
	return meta, nil
}

func (b *encblob) PutAll(m map[string]string) error {
	meta := make(map[string]string)
	for k, v := range m {
		enc, err := encrypt([]byte(v), b.pcipher)
		if err != nil {
			return err
		}
		meta[k] = string(enc)
	}
	return b.blob.PutAll(meta)
}

func (b *encblob) Reader() (io.Reader, error) {
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(b.scipher, iv[:])

	r, err := b.blob.Reader()
	if err != nil {
		return nil, err
	}

	b.r = &cipher.StreamReader{S: stream, R: r}
	return b.r, nil
}

func (b *encblob) Writer() (io.Writer, error) {
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(b.scipher, iv[:])

	w, err := b.blob.Writer()
	if err != nil {
		return nil, err
	}

	b.w = &cipher.StreamWriter{S: stream, W: w}
	return b.w, nil
}

func (b *encblob) Seal() error {
	return b.blob.Seal()
}

func (b *encblob) Close() error {
	return b.blob.Close()
}

func (b *encblob) Size() int64 {
	return b.blob.Size()
}

func (b *encblob) Timestamp() (time.Time, error) {
	return b.blob.Timestamp()
}

func (b *encblob) Verify() error {
	return b.blob.Verify()
}

type blob struct {
	f      string
	r      *os.File
	w      *os.File
	meta   string
	hasher *hasher
	sealed bool
}

func (b *blob) ID() string {
	_, file := filepath.Split(b.meta)
	return strings.TrimSuffix(file, filepath.Ext(file))
}

func (b *blob) Reader() (io.Reader, error) {
	var err error
	b.r, err = os.Open(b.f)
	if err != nil {
		return nil, err
	}
	return b.r, nil
}

func (b *blob) Writer() (io.Writer, error) {
	if b.sealed {
		return nil, ErrSealed
	}

	var err error
	b.w, err = os.Create(b.f)
	if err != nil {
		return nil, err
	}
	return io.MultiWriter(b.w, b.hasher), nil
}

func (b *blob) Get(k string) (string, error) {
	meta, err := b.readmeta()
	if err != nil {
		return "", err
	}

	if v, ok := meta[k]; ok {
		return v, nil
	}

	return "", ErrNotFound
}

func (b *blob) Put(k, v string) error {
	meta, err := b.readmeta()
	if err != nil {
		return err
	}

	meta[k] = v
	return b.writemeta(meta)
}

func (b *blob) GetAll() (map[string]string, error) {
	return b.readmeta()
}

func (b *blob) PutAll(m map[string]string) error {
	meta, err := b.readmeta()
	if err != nil {
		return err
	}

	for k, v := range m {
		meta[k] = v
	}

	return b.writemeta(meta)
}

func (b *blob) Seal() error {
	b.sealed = true

	sig := b.hasher.Sum(nil)
	return b.Put(KeySignature, hex.EncodeToString(sig))
}

func (b *blob) Size() int64 {
	if f, err := os.Open(b.f); err == nil {
		if info, err := f.Stat(); err == nil {
			return info.Size()
		}
	}
	return 0
}

func (b *blob) Timestamp() (time.Time, error) {
	f, err := os.Open(b.f)
	if err != nil {
		return time.Now(), err
	}

	info, err := f.Stat()
	if err != nil {
		return time.Now(), err
	}
	return info.ModTime(), nil
}

func (b *blob) Close() error {
	var (
		err1 error
		err2 error
	)
	if b.r != nil {
		err1 = b.r.Close()
	}

	if b.w != nil {
		err2 = b.w.Close()
	}

	if err1 != nil {
		return err1
	}

	return err2
}

func (b *blob) Verify() error {
	s, err := b.Get(KeySignature)
	if err != nil {
		return ErrSigNotFound
	}

	sig, err := hex.DecodeString(s)
	if err != nil {
		return err
	}

	f, err := os.Open(b.f)
	if err != nil {
		return err
	}

	hasher := newHasher(b.hasher.secret)
	if _, err = io.Copy(hasher, f); err != nil {
		return err
	}

	if !hasher.Equal(sig) {
		return ErrSigMisMatch
	}

	return nil
}

func (b *blob) readmeta() (map[string]string, error) {
	p, err := ioutil.ReadFile(b.meta)
	if err != nil {
		return nil, fmt.Errorf("failed to read meta file. error: %w", err)
	}

	meta := make(map[string]string)
	if len(p) == 0 {
		return meta, nil
	}

	if err := json.Unmarshal(p, &meta); err != nil {
		return nil, fmt.Errorf("blob: failed to unmarshal. error: %w", err)
	}
	return meta, nil
}

func (b *blob) writemeta(meta map[string]string) error {
	p, err := json.MarshalIndent(meta, "", "    ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(b.meta, p, 0660)
}

func encrypt(plainmsg []byte, aead cipher.AEAD) (string, error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plainmsg)+aead.Overhead())
	if _, err := crand.Read(nonce); err != nil {
		return "", err
	}

	encmsg := aead.Seal(nonce, nonce, plainmsg, nil)
	return hex.EncodeToString(encmsg), nil
}

func decrypt(encmsg string, aead cipher.AEAD) ([]byte, error) {
	msg, err := hex.DecodeString(encmsg)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext := msg[:aead.NonceSize()], msg[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

type hasher struct {
	secret []byte
	hash   hash.Hash
}

func newHasher(secret []byte) *hasher {
	return &hasher{secret: secret, hash: hmac.New(sha256.New, secret)}
}

func (h *hasher) Write(p []byte) (n int, err error) {
	return h.hash.Write(p)
}

func (h *hasher) Sum(p []byte) []byte {
	return h.hash.Sum(p)
}

func (h *hasher) Equal(sig []byte) bool {
	return hmac.Equal(sig, h.Sum(nil))
}
