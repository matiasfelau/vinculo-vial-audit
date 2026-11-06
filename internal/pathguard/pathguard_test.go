package pathguard

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// repo crea un directorio que simula un repositorio git.
func repo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRechazaRutasDentroDeUnRepositorio(t *testing.T) {
	root := repo(t)
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}

	casos := map[string]string{
		"la raíz del repo":                     root,
		"un archivo nuevo en la raíz":          filepath.Join(root, "clave.key"),
		"un subdirectorio existente":           nested,
		"un archivo nuevo en un subdirectorio": filepath.Join(nested, "clave.key"),
		"un subdirectorio que no existe":       filepath.Join(root, "no", "existe", "clave.key"),
	}
	for nombre, path := range casos {
		t.Run(nombre, func(t *testing.T) {
			if err := EnsureOutsideRepo(path); !errors.Is(err, ErrInsideRepo) {
				t.Fatalf("esperaba ErrInsideRepo, obtuvo %v", err)
			}
		})
	}
}

func TestRechazaRutasRelativasDentroDeUnRepositorio(t *testing.T) {
	root := repo(t)
	t.Chdir(root)

	if err := EnsureOutsideRepo("clave.key"); !errors.Is(err, ErrInsideRepo) {
		t.Fatalf("esperaba ErrInsideRepo para una ruta relativa, obtuvo %v", err)
	}
}

func TestRechazaUnWorktreeDondeGitEsUnArchivo(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: /otro/lugar"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := EnsureOutsideRepo(filepath.Join(root, "clave.key")); !errors.Is(err, ErrInsideRepo) {
		t.Fatalf("esperaba ErrInsideRepo, obtuvo %v", err)
	}
}

func TestAceptaRutasFueraDeUnRepositorio(t *testing.T) {
	outside := t.TempDir()

	for _, path := range []string{outside, filepath.Join(outside, "clave.key"), filepath.Join(outside, "nuevo", "dir", "clave.key")} {
		if err := EnsureOutsideRepo(path); err != nil {
			t.Errorf("%s: no se esperaba error: %v", path, err)
		}
	}
}

func TestRechazaUnSymlinkHaciaUnRepositorio(t *testing.T) {
	root := repo(t)
	link := filepath.Join(t.TempDir(), "enlace")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("no se pueden crear symlinks en este entorno: %v", err)
	}

	if err := EnsureOutsideRepo(filepath.Join(link, "clave.key")); !errors.Is(err, ErrInsideRepo) {
		t.Fatalf("un symlink hacia un repo no debe evadir el control, obtuvo %v", err)
	}
}

func TestCreateFileCreaConPermisosRestrictivosYNoSobrescribe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "clave.key")

	file, err := CreateFile(path)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	_ = file.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 && runtime.GOOS != "windows" {
		t.Errorf("permisos = %v, esperaba 0600", perm)
	}
	if _, err := CreateFile(path); err == nil {
		t.Fatal("no debe sobrescribir un archivo existente")
	}
}

func TestCreateFileEnUnRepositorioFalla(t *testing.T) {
	root := repo(t)

	file, err := CreateFile(filepath.Join(root, "clave.key"))

	if !errors.Is(err, ErrInsideRepo) {
		t.Fatalf("esperaba ErrInsideRepo, obtuvo %v", err)
	}
	if file != nil {
		_ = file.Close()
	}
	if _, statErr := os.Stat(filepath.Join(root, "clave.key")); statErr == nil {
		t.Error("no debe crear el archivo dentro del repo")
	}
}

func TestMkdirAllEnUnRepositorioFalla(t *testing.T) {
	root := repo(t)

	if err := MkdirAll(filepath.Join(root, "export")); !errors.Is(err, ErrInsideRepo) {
		t.Fatalf("esperaba ErrInsideRepo, obtuvo %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "export")); err == nil {
		t.Error("no debe crear el directorio dentro del repo")
	}
}
