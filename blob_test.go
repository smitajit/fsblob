package fsblob_test

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"

	crand "crypto/rand"

	"github.com/smitajit/fsblob"
	"golang.org/x/crypto/chacha20poly1305"
)

func ExampleNewBucket_encrypted() {
	path, clean, err := tempdir()
	if err != nil {
		log.Fatal(err)
	}
	defer clean()

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

	blob, err := bucket.New("demo-blob")
	if err != nil {
		log.Fatal(err)
	}

	if err := blob.Put("foo", "bar"); err != nil {
		log.Fatal(err)
	}

	w, err := blob.Writer()
	if err != nil {
		log.Fatal(err)
	}

	if _, err := fmt.Fprintf(w, "hello world"); err != nil {
		log.Fatal(err)
	}

	val, err := blob.Get("foo")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("value: ", val)

	r, err := blob.Reader()
	if err != nil {
		log.Fatal(err)
	}

	p, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("content: ", string(p))
	// Output:
	// value:  bar
	// content:  hello world
}

func ExampleNewBucket() {
	path, clean, err := tempdir()
	if err != nil {
		log.Fatal(err)
	}
	defer clean()

	bucket, err := fsblob.NewBucket(path, nil)
	if err != nil {
		log.Fatal(err)
	}

	blob, err := bucket.New("demo-blob")
	if err != nil {
		log.Fatal(err)
	}

	if err := blob.Put("foo", "bar"); err != nil {
		log.Fatal(err)
	}

	w, err := blob.Writer()
	if err != nil {
		log.Fatal(err)
	}

	if _, err := fmt.Fprintf(w, "hello world"); err != nil {
		log.Fatal(err)
	}

	val, err := blob.Get("foo")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("value: ", val)

	r, err := blob.Reader()
	if err != nil {
		log.Fatal(err)
	}

	p, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("content: ", string(p))
	// Output:
	// value:  bar
	// content:  hello world
}

func ExampleBucket_ListBuckets() {
	path, clean, err := tempdir()
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println(path)
	defer clean()

	b, err := fsblob.NewBucket(path, nil)
	if err != nil {
		log.Fatal(err)
	}

	_, err = b.Child("sub-bucket-1")
	if err != nil {
		log.Fatal(err)
	}

	_, err = b.Child("sub-bucket-2")
	if err != nil {
		log.Fatal(err)
	}

	b.ListBuckets(func(b *fsblob.Bucket) error {
		fmt.Println(b.ID())
		return nil
	})
	// Output:
	// sub-bucket-1
	// sub-bucket-2
}

func ExampleBucket_ListBlobs() {
	path, clean, err := tempdir()
	if err != nil {
		log.Fatal(err)
	}
	// fmt.Println(path)
	defer clean()

	b, err := fsblob.NewBucket(path, nil)
	if err != nil {
		log.Fatal(err)
	}

	_, err = b.New("blob-1")
	if err != nil {
		log.Fatal(err)
	}

	_, err = b.New("blob-2")
	if err != nil {
		log.Fatal(err)
	}

	b.ListBlobs(func(b fsblob.Blob) error {
		fmt.Println(b.ID())
		return nil
	})
	// Output:
	// blob-1
	// blob-2
}

func TestBlobSeal(t *testing.T) {
	dir, clean, err := tempdir()
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	bucket, err := fsblob.NewBucket(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	b, err := bucket.New("blob-1")
	if err != nil {
		t.Fatal(err)
	}

	w, err := b.Writer()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Fprintf(w, "hello world")

	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}

	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	b, err = bucket.Open("blob-1")
	if err != nil {
		t.Fatal(err)
	}

	if err = b.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestBlobSeal_corrupted(t *testing.T) {
	dir, clean, err := tempdir()
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	bucket, err := fsblob.NewBucket(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	b, err := bucket.New("blob-1")
	if err != nil {
		t.Fatal(err)
	}

	w, err := b.Writer()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Fprintf(w, "hello world")

	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}

	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(filepath.Join(bucket.Path(), "blob-1.blob"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, "a")
	_ = f.Close()

	b, err = bucket.Open("blob-1")
	if err != nil {
		t.Fatal(err)
	}

	if err = b.Verify(); err != fsblob.ErrSigMisMatch {
		t.Fatal(err)
	}
}

func TestBlobSeal_deny(t *testing.T) {
	dir, clean, err := tempdir()
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	bucket, err := fsblob.NewBucket(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	b, err := bucket.New("blob-1")
	if err != nil {
		t.Fatal(err)
	}

	w, err := b.Writer()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Fprintf(w, "hello world")

	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}

	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	b, err = bucket.Open("blob-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := b.Writer(); err != fsblob.ErrSealed {
		t.Fatal("error expected")
	}
}

func TestBlobSeal_encrypted(t *testing.T) {
	dir, clean, err := tempdir()
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	key := make([]byte, 32)
	if _, err := crand.Read(key); err != nil {
		log.Fatal(err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}

	bucket, err := fsblob.NewBucket(dir, aead)
	if err != nil {
		t.Fatal(err)
	}

	b, err := bucket.New("blob-1")
	if err != nil {
		t.Fatal(err)
	}

	w, err := b.Writer()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Fprintf(w, "hello world")

	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}

	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	b, err = bucket.Open("blob-1")
	if err != nil {
		t.Fatal(err)
	}

	if err = b.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestBlobSize(t *testing.T) {
	dir, clean, err := tempdir()
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	bucket, err := fsblob.NewBucket(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	b, err := bucket.New("blob-1")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	if size := b.Size(); size != 0 {
		t.Fatal("expected size. expected: 0, got: ", size)
	}

	w, err := b.Writer()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(w, "hello world")

	b, err = bucket.Open("blob-1")
	if err != nil {
		t.Fatal(err)
	}

	if size := b.Size(); size != 11 {
		t.Fatal("expected size. expected: 11, got: ", size)
	}
}

func TestBlobPutAll(t *testing.T) {
	dir, clean, err := tempdir()
	if err != nil {
		t.Fatal(err)
	}
	defer clean()

	bucket, err := fsblob.NewBucket(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	b, err := bucket.New("blob-1")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	if err := b.PutAll(map[string]string{
		"key-1": "val-1",
		"key-2": "val-2",
	}); err != nil {
		t.Fatal(err)
	}

	m, err := b.GetAll()
	if err != nil {
		t.Fatal(err)
	}

	if v, ok := m["key-1"]; !ok || v != "val-1" {
		t.Fatalf("expected: val-1, got: %s", v)
	}

	if v, ok := m["key-2"]; !ok || v != "val-2" {
		t.Fatalf("expected: val-2, got: %s", v)
	}
}

type cleanfn func() error

func tempdir() (string, cleanfn, error) {
	dir, err := os.MkdirTemp(os.TempDir(), "blob")
	if err != nil {
		return "", nil, err
	}
	return dir, func() error {
		return os.RemoveAll(dir)
	}, nil
}
