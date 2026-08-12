// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package encryption_test

import (
	"bytes"
	"context"
	stdio "io"
	"io/fs"
	"testing"

	"github.com/apache/iceberg-go/encryption"
	icebergio "github.com/apache/iceberg-go/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// In-memory io.IO stubs
// ---------------------------------------------------------------------------

// fakeIO is a read-only in-memory icebergio.IO that tracks whether the files
// it hands out get closed.
type fakeIO struct {
	files  map[string][]byte
	opened []*trackedFile
}

func newFakeIO() *fakeIO { return &fakeIO{files: map[string][]byte{}} }

func (f *fakeIO) Open(name string) (icebergio.File, error) {
	data, ok := f.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	tf := &trackedFile{Reader: bytes.NewReader(bytes.Clone(data))}
	f.opened = append(f.opened, tf)

	return tf, nil
}

func (f *fakeIO) Remove(name string) error {
	delete(f.files, name)

	return nil
}

type trackedFile struct {
	*bytes.Reader
	closed bool
}

func (t *trackedFile) Stat() (fs.FileInfo, error) { return nil, nil }

func (t *trackedFile) Close() error {
	t.closed = true

	return nil
}

// fakeWriteIO adds write support to fakeIO.
type fakeWriteIO struct {
	*fakeIO
	created []*trackedWriter
}

func newFakeWriteIO() *fakeWriteIO { return &fakeWriteIO{fakeIO: newFakeIO()} }

func (f *fakeWriteIO) Create(name string) (icebergio.FileWriter, error) {
	tw := &trackedWriter{commit: func(b []byte) { f.files[name] = b }}
	f.created = append(f.created, tw)

	return tw, nil
}

func (f *fakeWriteIO) WriteFile(name string, p []byte) error {
	f.files[name] = bytes.Clone(p)

	return nil
}

type trackedWriter struct {
	buf    bytes.Buffer
	commit func([]byte)
	closed bool
}

func (t *trackedWriter) Write(p []byte) (int, error) { return t.buf.Write(p) }

func (t *trackedWriter) ReadFrom(r stdio.Reader) (int64, error) { return t.buf.ReadFrom(r) }

func (t *trackedWriter) Close() error {
	t.closed = true
	t.commit(t.buf.Bytes())

	return nil
}

// ---------------------------------------------------------------------------
// A minimal EncryptionManager that actually transforms bytes
// ---------------------------------------------------------------------------

// xorManager is a stand-in for a real EncryptionManager. It XORs every byte
// with 0xFF, which is length-preserving and lets tests assert that bytes
// travel through the manager rather than around it.
type xorManager struct{}

const xorKeyMetadata = "xor-v1"

func xorBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ 0xFF
	}

	return out
}

func (xorManager) NewEncryptedOutputFile(_ context.Context, w icebergio.FileWriter, keyID string) (encryption.EncryptedOutputFile, error) {
	return &xorOutputFile{w: w, keyID: keyID}, nil
}

func (xorManager) NewDecryptedInputFile(_ context.Context, f icebergio.File, km encryption.EncryptionKeyMetadata) (encryption.EncryptedInputFile, error) {
	ciphertext, err := stdio.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return &xorInputFile{
		Reader: bytes.NewReader(xorBytes(ciphertext)),
		src:    f,
		km:     km,
	}, nil
}

type xorOutputFile struct {
	w     icebergio.FileWriter
	buf   bytes.Buffer
	keyID string
}

func (x *xorOutputFile) Write(p []byte) (int, error) { return x.buf.Write(p) }

func (x *xorOutputFile) ReadFrom(r stdio.Reader) (int64, error) { return x.buf.ReadFrom(r) }

func (x *xorOutputFile) Close() error {
	if _, err := x.w.Write(xorBytes(x.buf.Bytes())); err != nil {
		return err
	}

	return x.w.Close()
}

func (x *xorOutputFile) KeyMetadata() encryption.EncryptionKeyMetadata {
	return encryption.EncryptionKeyMetadata(xorKeyMetadata + ":" + x.keyID)
}

type xorInputFile struct {
	*bytes.Reader
	src icebergio.File
	km  encryption.EncryptionKeyMetadata
}

func (x *xorInputFile) Stat() (fs.FileInfo, error) { return x.src.Stat() }
func (x *xorInputFile) Close() error               { return x.src.Close() }

func (x *xorInputFile) KeyMetadata() encryption.EncryptionKeyMetadata { return x.km }

// ---------------------------------------------------------------------------
// Open / OpenDecrypted
// ---------------------------------------------------------------------------

func TestEncryptingFileIO_OpenIsPassThrough(t *testing.T) {
	inner := newFakeIO()
	inner.files["a.parquet"] = []byte("raw bytes")

	fio := encryption.NewEncryptingFileIO(inner, xorManager{})

	f, err := fio.Open("a.parquet")
	require.NoError(t, err)
	defer f.Close()

	got, err := stdio.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, []byte("raw bytes"), got, "Open must not decrypt; a path alone does not identify a key")
}

func TestEncryptingFileIO_OpenDecrypted_EmptyKeyMetadataReadsPlain(t *testing.T) {
	inner := newFakeIO()
	inner.files["a.parquet"] = []byte("plaintext table data")

	fio := encryption.NewEncryptingFileIO(inner, xorManager{})

	f, err := fio.OpenDecrypted(t.Context(), "a.parquet", nil)
	require.NoError(t, err)
	defer f.Close()

	got, err := stdio.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, []byte("plaintext table data"), got, "an unencrypted file must stay readable through an EncryptingFileIO")
	assert.Empty(t, f.KeyMetadata())
}

func TestEncryptingFileIO_OpenDecrypted_MissingFile(t *testing.T) {
	fio := encryption.NewEncryptingFileIO(newFakeIO(), xorManager{})

	_, err := fio.OpenDecrypted(t.Context(), "nope.parquet", encryption.EncryptionKeyMetadata(xorKeyMetadata))
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestEncryptingFileIO_OpenDecrypted_ClosesFileWhenManagerRejects(t *testing.T) {
	inner := newFakeIO()
	inner.files["a.parquet"] = []byte("ciphertext")

	// PlaintextEncryptionManager fails closed on non-empty key metadata.
	fio := encryption.NewEncryptingFileIO(inner, encryption.PlaintextEncryptionManager{})

	_, err := fio.OpenDecrypted(t.Context(), "a.parquet", encryption.EncryptionKeyMetadata("km"))
	require.ErrorIs(t, err, encryption.ErrKeyMetadataNotSupported)

	require.Len(t, inner.opened, 1)
	assert.True(t, inner.opened[0].closed, "the underlying file must be closed when the manager rejects it")
}

// ---------------------------------------------------------------------------
// Write path
// ---------------------------------------------------------------------------

func TestEncryptingFileIO_EncryptedRoundTrip(t *testing.T) {
	inner := newFakeWriteIO()

	fio, ok := encryption.NewEncryptingFileIO(inner, xorManager{}).(encryption.EncryptingWriteFileIO)
	require.True(t, ok, "a writable inner IO must yield an EncryptingWriteFileIO")

	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	out, err := fio.NewEncryptedOutput(t.Context(), "a.parquet", "kek-1")
	require.NoError(t, err)
	_, err = out.Write(plaintext)
	require.NoError(t, err)
	require.NoError(t, out.Close())

	km := out.KeyMetadata()
	require.NotEmpty(t, km, "key metadata must be available after Close")

	assert.NotEqual(t, plaintext, inner.files["a.parquet"], "bytes at rest must not be plaintext")

	in, err := fio.OpenDecrypted(t.Context(), "a.parquet", km)
	require.NoError(t, err)
	defer in.Close()

	got, err := stdio.ReadAll(in)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
	assert.Equal(t, km, in.KeyMetadata())
}

func TestEncryptingFileIO_NewEncryptedOutput_ClosesWriterWhenManagerRejects(t *testing.T) {
	inner := newFakeWriteIO()

	fio := encryption.NewEncryptingFileIO(inner, encryption.PlaintextEncryptionManager{}).(encryption.EncryptingWriteFileIO)

	_, err := fio.NewEncryptedOutput(t.Context(), "a.parquet", "kek-1")
	require.ErrorIs(t, err, encryption.ErrKeyIDNotSupported)

	require.Len(t, inner.created, 1)
	assert.True(t, inner.created[0].closed, "the created writer must be closed when the manager rejects it")
}

func TestEncryptingFileIO_CreateAndWriteFileStayUnencrypted(t *testing.T) {
	inner := newFakeWriteIO()

	fio := encryption.NewEncryptingFileIO(inner, xorManager{}).(encryption.EncryptingWriteFileIO)

	w, err := fio.Create("a.parquet")
	require.NoError(t, err)
	_, err = w.Write([]byte("plain"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	assert.Equal(t, []byte("plain"), inner.files["a.parquet"], "Create must stay a pass-through; encryption is opt-in per file")

	require.NoError(t, fio.WriteFile("b.parquet", []byte("also plain")))
	assert.Equal(t, []byte("also plain"), inner.files["b.parquet"])
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNewEncryptingFileIO_ReadOnlyInnerIsNotWritable(t *testing.T) {
	fio := encryption.NewEncryptingFileIO(newFakeIO(), xorManager{})

	_, ok := fio.(encryption.EncryptingWriteFileIO)
	assert.False(t, ok, "a read-only inner IO must not present a write capability")

	_, ok = fio.(icebergio.WriteFileIO)
	assert.False(t, ok)
}

func TestNewEncryptingFileIO_NilManagerDefaultsToPlaintext(t *testing.T) {
	fio := encryption.NewEncryptingFileIO(newFakeIO(), nil)

	assert.IsType(t, encryption.PlaintextEncryptionManager{}, fio.Manager())
}

func TestNewEncryptingFileIO_RewrapsInsteadOfNesting(t *testing.T) {
	inner := newFakeIO()

	once := encryption.NewEncryptingFileIO(inner, encryption.PlaintextEncryptionManager{})
	twice := encryption.NewEncryptingFileIO(once, xorManager{})

	assert.Same(t, inner, twice.Inner(), "re-wrapping must rebind the original IO, not nest wrappers")
	assert.IsType(t, xorManager{}, twice.Manager())
}

func TestEncryptingFileIO_Remove(t *testing.T) {
	inner := newFakeIO()
	inner.files["a.parquet"] = []byte("data")

	fio := encryption.NewEncryptingFileIO(inner, xorManager{})

	require.NoError(t, fio.Remove("a.parquet"))
	assert.NotContains(t, inner.files, "a.parquet")
}

// ---------------------------------------------------------------------------
// OpenMaybeEncrypted
// ---------------------------------------------------------------------------

func TestOpenMaybeEncrypted_NoKeyMetadataOpensPlain(t *testing.T) {
	inner := newFakeIO()
	inner.files["a.parquet"] = []byte("plain")

	f, err := encryption.OpenMaybeEncrypted(t.Context(), inner, "a.parquet", nil)
	require.NoError(t, err)
	defer f.Close()

	got, err := stdio.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, []byte("plain"), got)
}

func TestOpenMaybeEncrypted_DecryptsThroughEncryptingFileIO(t *testing.T) {
	inner := newFakeIO()
	inner.files["a.parquet"] = xorBytes([]byte("secret rows"))

	fio := encryption.NewEncryptingFileIO(inner, xorManager{})

	f, err := encryption.OpenMaybeEncrypted(t.Context(), fio, "a.parquet", encryption.EncryptionKeyMetadata(xorKeyMetadata))
	require.NoError(t, err)
	defer f.Close()

	got, err := stdio.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret rows"), got)
}

func TestOpenMaybeEncrypted_PlainIOWithKeyMetadataFailsClosed(t *testing.T) {
	inner := newFakeIO()
	inner.files["a.parquet"] = xorBytes([]byte("secret rows"))

	_, err := encryption.OpenMaybeEncrypted(t.Context(), inner, "a.parquet", encryption.EncryptionKeyMetadata(xorKeyMetadata))
	require.ErrorIs(t, err, encryption.ErrEncryptionNotConfigured,
		"key metadata without an EncryptingFileIO must not silently return ciphertext")
}
