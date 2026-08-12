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

package encryption

import (
	"context"
	"errors"

	icebergio "github.com/apache/iceberg-go/io"
)

// ErrEncryptionNotConfigured is returned by [OpenMaybeEncrypted] when a file
// carries key metadata but the [icebergio.IO] it is being opened through is
// not an [EncryptingFileIO]. Returning the raw bytes would fail open: the
// caller would read ciphertext as if it were plaintext.
var ErrEncryptionNotConfigured = errors.New("encryption: file has key metadata but no EncryptingFileIO is configured")

// EncryptingFileIO pairs an [icebergio.IO] with an [EncryptionManager]. It
// mirrors Java's EncryptingFileIO.
//
// Open is a plain pass-through: a path alone does not identify a key, so
// decryption goes through OpenDecrypted, which takes the per-file key metadata
// the caller already holds (DataFile.KeyMetadata, ManifestFile.KeyMetadata,
// StatisticsFile.KeyMetadata).
//
// The wrapper implements [icebergio.IO], and [icebergio.WriteFileIO] when the
// wrapped IO does. Other optional capabilities of the wrapped IO
// (ReadFileIO, ListableIO, BulkRemovableIO, ...) are not currently forwarded;
// reach them through Inner.
type EncryptingFileIO interface {
	icebergio.IO

	// Inner returns the wrapped IO.
	Inner() icebergio.IO

	// Manager returns the encryption manager.
	Manager() EncryptionManager

	// OpenDecrypted opens name and decrypts it using keyMetadata. Empty
	// keyMetadata means the file is not encrypted and is returned as-is.
	OpenDecrypted(ctx context.Context, name string, keyMetadata EncryptionKeyMetadata) (EncryptedInputFile, error)
}

// EncryptingWriteFileIO is an [EncryptingFileIO] whose wrapped IO supports
// writes. [NewEncryptingFileIO] returns a value satisfying it whenever the
// wrapped IO implements [icebergio.WriteFileIO].
type EncryptingWriteFileIO interface {
	EncryptingFileIO
	icebergio.WriteFileIO

	// NewEncryptedOutput creates name and returns a writer that encrypts what
	// is written to it. keyID names the KEK used to wrap the file's generated
	// data key. The key metadata to persist in the manifest entry is available
	// from the returned file once it has been closed.
	NewEncryptedOutput(ctx context.Context, name, keyID string) (EncryptedOutputFile, error)
}

// NewEncryptingFileIO wraps inner with mgr. A nil mgr means
// [PlaintextEncryptionManager]. Re-wrapping an [EncryptingFileIO] rebinds the
// original IO to mgr rather than nesting.
func NewEncryptingFileIO(inner icebergio.IO, mgr EncryptionManager) EncryptingFileIO {
	if mgr == nil {
		mgr = PlaintextEncryptionManager{}
	}

	if already, ok := inner.(EncryptingFileIO); ok {
		inner = already.Inner()
	}

	base := encryptingFileIO{inner: inner, mgr: mgr}
	if wio, ok := inner.(icebergio.WriteFileIO); ok {
		return &encryptingWriteFileIO{encryptingFileIO: base, wio: wio}
	}

	return &base
}

// OpenMaybeEncrypted opens name through fio, decrypting it when keyMetadata is
// non-empty. It is the read seam for files whose key metadata travels with the
// manifest entry rather than the path.
//
// It fails closed: non-empty keyMetadata with a plain [icebergio.IO] returns
// [ErrEncryptionNotConfigured] rather than handing back ciphertext.
func OpenMaybeEncrypted(ctx context.Context, fio icebergio.IO, name string, keyMetadata EncryptionKeyMetadata) (icebergio.File, error) {
	if len(keyMetadata) == 0 {
		return fio.Open(name)
	}

	efio, ok := fio.(EncryptingFileIO)
	if !ok {
		return nil, ErrEncryptionNotConfigured
	}

	return efio.OpenDecrypted(ctx, name, keyMetadata)
}

type encryptingFileIO struct {
	inner icebergio.IO
	mgr   EncryptionManager
}

var _ EncryptingFileIO = (*encryptingFileIO)(nil)

func (e *encryptingFileIO) Inner() icebergio.IO        { return e.inner }
func (e *encryptingFileIO) Manager() EncryptionManager { return e.mgr }
func (e *encryptingFileIO) Remove(name string) error   { return e.inner.Remove(name) }

// Open returns the raw file without decryption. Callers holding key metadata
// should use OpenDecrypted.
func (e *encryptingFileIO) Open(name string) (icebergio.File, error) {
	return e.inner.Open(name)
}

func (e *encryptingFileIO) OpenDecrypted(ctx context.Context, name string, keyMetadata EncryptionKeyMetadata) (EncryptedInputFile, error) {
	f, err := e.inner.Open(name)
	if err != nil {
		return nil, err
	}

	if len(keyMetadata) == 0 {
		return &plaintextInputFile{File: f}, nil
	}

	dec, err := e.mgr.NewDecryptedInputFile(ctx, f, keyMetadata)
	if err != nil {
		f.Close()

		return nil, err
	}

	return dec, nil
}

type encryptingWriteFileIO struct {
	encryptingFileIO
	wio icebergio.WriteFileIO
}

var _ EncryptingWriteFileIO = (*encryptingWriteFileIO)(nil)

// Create returns an unencrypted writer. Encryption is opt-in per file via
// NewEncryptedOutput, which is the only path that produces key metadata.
func (e *encryptingWriteFileIO) Create(name string) (icebergio.FileWriter, error) {
	return e.wio.Create(name)
}

// WriteFile writes p unencrypted, for the same reason as Create.
func (e *encryptingWriteFileIO) WriteFile(name string, p []byte) error {
	return e.wio.WriteFile(name, p)
}

func (e *encryptingWriteFileIO) NewEncryptedOutput(ctx context.Context, name, keyID string) (EncryptedOutputFile, error) {
	w, err := e.wio.Create(name)
	if err != nil {
		return nil, err
	}

	out, err := e.mgr.NewEncryptedOutputFile(ctx, w, keyID)
	if err != nil {
		w.Close()

		return nil, err
	}

	return out, nil
}
