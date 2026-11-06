// Package pathguard impide que las CLIs de Audit escriban material sensible (la
// clave privada, los datos abiertos, las exportaciones) dentro de un repositorio
// git, donde terminaría versionado por accidente.
package pathguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrInsideRepo indica que la ruta está dentro de un repositorio git.
var ErrInsideRepo = errors.New("la ruta está dentro de un repositorio git")

const gitMarker = ".git"

// EnsureOutsideRepo devuelve ErrInsideRepo si path (que puede no existir todavía)
// está dentro de un repositorio git: es decir, si él o alguno de sus ancestros
// contiene una entrada .git (directorio, o archivo en worktrees y submódulos). Los
// symlinks se resuelven antes de recorrer los ancestros, de modo que un enlace
// hacia un repo no evade el control.
func EnsureOutsideRepo(path string) error {
	resolved, err := resolve(path)
	if err != nil {
		return fmt.Errorf("pathguard: no se pudo resolver la ruta: %w", err)
	}

	for dir := startDir(resolved); ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(filepath.Join(dir, gitMarker)); err == nil {
			return ErrInsideRepo
		} else if !errors.Is(err, os.ErrNotExist) {
			// Fail-closed: si no se puede determinar, se rechaza.
			return fmt.Errorf("pathguard: no se pudo inspeccionar %q: %w", dir, err)
		}

		if parent := filepath.Dir(dir); parent == dir {
			return nil
		}
	}
}

// resolve devuelve la ruta absoluta de path con los symlinks de su ancestro
// existente más profundo resueltos, más el resto (todavía inexistente) sin tocar.
func resolve(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	existing, rest := abs, ""
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(existing), rest)
		existing = parent
	}

	target, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", err
	}
	return filepath.Join(target, rest), nil
}

// startDir devuelve el directorio desde el que se busca .git: la propia ruta si es
// un directorio existente, o su directorio padre si es un archivo o no existe.
func startDir(path string) string {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return path
	}
	return filepath.Dir(path)
}

const (
	dirPerm  = 0o700
	filePerm = 0o600
)

// MkdirAll crea el directorio (y sus padres) con permisos 0700, después de
// verificar que esté fuera de un repositorio git.
func MkdirAll(dir string) error {
	if err := EnsureOutsideRepo(dir); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("no se pudo crear el directorio %s: %w", dir, err)
	}
	return nil
}

// CreateFile crea un archivo nuevo con permisos 0600, después de verificar que
// esté fuera de un repositorio git. Falla si el archivo ya existe: nunca
// sobrescribe.
func CreateFile(path string) (*os.File, error) {
	if err := EnsureOutsideRepo(path); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return nil, fmt.Errorf("no se pudo crear el directorio de %s: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		return nil, fmt.Errorf("no se pudo crear %s: %w", path, err)
	}
	return file, nil
}
