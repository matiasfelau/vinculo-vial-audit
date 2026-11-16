package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matiasfelau/vinculo-vial-audit/pkg/config"
)

func TestWithoutContextDelegaEnElChequeoLocal(t *testing.T) {
	casos := []struct {
		nombre string
		check  bool
	}{
		{"saludable", true},
		{"caído", false},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			llamadas := 0
			adaptado := withoutContext(func() bool {
				llamadas++
				return c.check
			})

			if got := adaptado(context.Background()); got != c.check {
				t.Errorf("withoutContext devolvió %v, esperaba %v", got, c.check)
			}
			if llamadas != 1 {
				t.Errorf("el chequeo se invocó %d veces, esperaba 1", llamadas)
			}
		})
	}
}

func TestStorageConfigUsaElBucketIndicadoYLosParametrosDeS3(t *testing.T) {
	cfg := &config.Config{
		ObjectLockMode: config.LockModeGovernance,
		S3: config.S3{
			Region:              "sa-east-1",
			PutTimeout:          3 * time.Second,
			GetTimeout:          4 * time.Second,
			MaxObjectBytes:      1234,
			BreakerThreshold:    7,
			BreakerWindow:       5 * time.Second,
			BreakerOpenDuration: 6 * time.Second,
		},
	}

	got := storageConfig(cfg, "bucket-de-prueba")

	if got.Bucket != "bucket-de-prueba" {
		t.Errorf("Bucket = %q, esperaba bucket-de-prueba", got.Bucket)
	}
	if got.LockMode != config.LockModeGovernance {
		t.Errorf("LockMode = %q, esperaba %q", got.LockMode, config.LockModeGovernance)
	}
	if got.Region != "sa-east-1" || got.PutTimeout != 3*time.Second || got.GetTimeout != 4*time.Second || got.MaxObjectBytes != 1234 {
		t.Errorf("los parámetros de S3 no se copiaron: %+v", got)
	}
	if got.BreakerThreshold != 7 || got.BreakerWindow != 5*time.Second || got.BreakerOpenDuration != 6*time.Second {
		t.Errorf("los parámetros del breaker no se copiaron: %+v", got)
	}
}

func TestWaitBackgroundVuelveEnCuantoTerminaElTrabajo(t *testing.T) {
	var background sync.WaitGroup
	background.Add(1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		background.Done()
	}()

	inicio := time.Now()
	waitBackground(&background, 5*time.Second)

	if espera := time.Since(inicio); espera > 2*time.Second {
		t.Errorf("waitBackground esperó %v aunque el trabajo terminó enseguida", espera)
	}
}

func TestWaitBackgroundSeRindeAlVencerElPlazoYLoAvisa(t *testing.T) {
	var logs bytes.Buffer
	previo := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previo) })

	var background sync.WaitGroup
	background.Add(1) // nunca termina
	t.Cleanup(background.Done)

	inicio := time.Now()
	waitBackground(&background, 50*time.Millisecond)

	if espera := time.Since(inicio); espera < 50*time.Millisecond {
		t.Errorf("waitBackground volvió a los %v, antes del plazo", espera)
	}
	if !strings.Contains(logs.String(), "no terminó a tiempo") {
		t.Errorf("no se avisó que el trabajo de fondo no terminó: %q", logs.String())
	}
}

func TestRunFallaSiLaBaseNoEsAlcanzableYNoFiltraLaContrasena(t *testing.T) {
	const password = "clave-que-no-debe-aparecer"
	cfg := &config.Config{
		// El puerto 1 no tiene a nadie escuchando: la conexión se rechaza al instante.
		DatabaseURL: "postgres://audit:" + password + "@127.0.0.1:1/audit?sslmode=disable&connect_timeout=1",
	}

	err := run(context.Background(), cfg)

	if err == nil {
		t.Fatal("run devolvió nil con la base inalcanzable")
	}
	if strings.Contains(err.Error(), password) {
		t.Errorf("el error de run filtra la contraseña de la base: %v", err)
	}
}
