# vinculo-vial-audit

Audit Service de la plataforma Vínculo Vial (US-11). Conserva, aislado e inmutable, el
registro de cada alerta que llegó a un destinatario, para presentarlo ante un
requerimiento judicial.

## Qué hace y qué no

**Hace:**

- Consume los eventos `audit.alert.recorded`, `audit.alert.delivered` y
  `audit.alert.discarded` que publica Alert.
- Guarda por cada alerta un registro con el DNI del emisor y la patente denunciada
  **cifrados hacia la clave pública de Audit** (los sella Identity y Vehicle; Audit los guarda
  tal como llegan).
- Al entregarse la alerta, copia las fotos redactadas a su propio bucket con **S3 Object Lock**
  hasta `destroy_at` (creación de la alerta + `AUDIT_RETENTION_DAYS`) y escribe un
  `manifest.json` bloqueado.
- Destruye los registros vencidos (sweeper), salvo los que tienen retención judicial.
- Ofrece CLIs para el procedimiento judicial: `audit-keygen`, `auditctl` y `audit-open`.

**No hace:**

- **No descifra nada.** No carga la clave privada de Audit ni las claves AES de otros
  servicios (`AES_KEY`, `PAT_AES_KEY`, cualquier `*_PRIVATE_KEY`): si alguna está definida en
  el entorno, el servicio no arranca.
- No tiene usuarios, endpoints públicos ni eventos propios. Su única superficie HTTP es
  `/health`, `/ready` y `/health/deps`, en un puerto que no se publica.
- No consume `user.deleted`: una baja de cuenta no toca su registro.
- No tiene interfaz para requerimientos judiciales (solo CLIs) ni búsqueda por DNI o patente.

## Arquitectura

Clean Architecture, como el resto de los servicios.

```
cmd/api                         Servicio (consumidores, sweeper, /health)
cmd/auditctl                    CLI: export y hold (usa la base y el bucket de Audit)
cmd/audit-keygen                CLI: genera el par X25519
cmd/audit-open                  CLI: abre los criptogramas, fuera de línea
internal/domain                 Entidades y errores, sin infraestructura
internal/manifest               Formato de manifest.json y claves de objeto (solo stdlib)
internal/service/record         Casos de uso recorded, delivered y discarded
internal/service/sweeper        Destrucción de registros vencidos
internal/service/export         auditctl export: manifiesto, fotos e informe de verificación
internal/service/hold           auditctl hold: retención judicial
internal/repository/postgres    Persistencia (GORM/pgx) y migraciones versionadas
internal/client/storage         S3 con Object Lock (breaker y timeouts por bucket)
internal/delivery/events        Consumidores RabbitMQ (ack manual, reintentos, DLQ)
internal/delivery/http          /health, /ready y /health/deps (Gin)
internal/auditcrypto            HPKE para las CLIs (circl). El servicio no lo importa
internal/opener                 Lógica de audit-open (sin red, base de datos ni AWS)
internal/pathguard              Rechaza escribir dentro de un repositorio git
pkg/config                      Configuración con validación fail-fast
```

`circl` (HPKE) solo se usa en `audit-keygen`, `audit-open` y los tests.

## Eventos y colas

Core declara las tres colas con su `.retry` y su `.dlq`. Audit es el único consumidor y no
declara topología.

| Cola | Evento (`eventType` = routing key) | Payload |
|---|---|---|
| `audit.alert-recorded.q` | `audit.alert.recorded` | `{ alert_id, alert_type, created_at, dni_enc_audit, pat_enc_audit, audit_key_id }` |
| `audit.alert-delivered.q` | `audit.alert.delivered` | `{ alert_id, delivered_at, bucket, evidence: [{ role, index, key, sha256 }] }` |
| `audit.alert-discarded.q` | `audit.alert.discarded` | `{ alert_id, reason }` con `reason` = `REJECTED`, `EXPIRED` o `UNCLAIMED` |

Comportamiento de cada consumidor:

- **recorded.** Valida los UUID, `alert_type` (`CRASHED` o `PARKED_ON_GARAGE`), `created_at`
  (RFC3339), `audit_key_id` y que los criptogramas sean base64 no vacío. Inserta con
  `ON CONFLICT DO NOTHING` y calcula `destroy_at`. Un `recorded` repetido no cambia nada.
- **delivered.** Si el registro no existe, es transitorio (`.retry`). Si ya está `DELIVERED`,
  hace ack. Valida que `bucket` sea `EVIDENCE_BUCKET` y que cada clave sea
  `alerts/{alert_id}/redacted/…`. Por cada foto: la lee, verifica el SHA-256 (si no coincide, DLQ)
  y la sube a `records/{alert_id}/{role}-{index}.jpg` con Object Lock hasta `destroy_at`.
  Después escribe `manifest.json` bloqueado y actualiza la fila en una transacción. Un
  reintento tras una subida parcial crea versiones nuevas: es aceptable, el sweeper borra todas.
- **discarded.** Si el registro no existe, es transitorio. Si está `RECORDED`, lo borra. Si está
  `DELIVERED`, hace ack sin borrar y registra un WARN solo con el `alert_id`: un registro
  entregado nunca se borra antes de su vencimiento.

Clasificación de errores:

| Tipo | Casos | Resultado |
|---|---|---|
| Permanente | payload ilegible o inválido, SHA-256 distinto, `destroy_at` ya vencido, panic del procesador | DLQ directa, sin reintento |
| Transitorio | registro inexistente (orden invertido), base o S3 caídos, circuito abierto | nack a `.retry`; tras `MAX_RETRIES`, DLQ |

Con `MAX_RETRIES=10` y el `RETRY_TTL_MS` de 30 s de Core, se cubren 5 minutos de desorden entre
`recorded` y `delivered`/`discarded`.

**Limitación conocida del contrato:** un `discarded` repetido *después* de que el registro ya se
borró se trata como "registro inexistente" (transitorio) y termina en la DLQ tras agotar los
reintentos. Es el comportamiento que fija el contrato; no hay lápida que permita distinguirlo.

## Base de datos

Base propia (`audit-db`), tabla `audit_records`, creada por las migraciones versionadas de
`internal/repository/postgres/migrations` (se aplican al arrancar, con un advisory lock para
réplicas concurrentes). Un trigger impide modificar los datos de origen de un registro
(`alert_id`, `alert_type`, `alert_created_at`, criptogramas, `audit_key_id`, `recorded_at` y
`destroy_at`); solo cambian el estado de entrega y `judicial_hold`.

## Bucket de Audit

Lo crea Core: privado, SSE-S3, versionado y con Object Lock. Claves:

- `records/{alert_id}/{role}-{index}.jpg`: copia de cada foto redactada.
- `records/{alert_id}/manifest.json`: `{ alert_id, alert_type, alert_created_at, delivered_at,
  dni_enc_audit, pat_enc_audit, audit_key_id, evidence: [{ role, index, key, sha256 }] }`.

El manifiesto bloqueado es la fuente de verdad; la fila es un índice. `auditctl export` verifica
la fila contra el manifiesto y el manifiesto contra las fotos.

## Variables de entorno

Ver [.env.example](.env.example). Las obligatorias no tienen valor por defecto: sin ellas el
proceso termina con código distinto de cero.

| Variable | Valor | Descripción |
|---|---|---|
| `DATABASE_URL` | obligatoria | Base propia. |
| `RABBITMQ_URL` | obligatoria | Broker. |
| `AUDIT_RETENTION_DAYS` | obligatoria (1095) | Días de conservación desde la creación de la alerta (art. 2561 del CCyC; cubre el art. 62 del CP). En desarrollo, un valor bajo. |
| `AUDIT_OBJECT_LOCK_MODE` | obligatoria | `GOVERNANCE` en desarrollo; `COMPLIANCE` solo en producción (ni root puede borrar antes de tiempo). |
| `AUDIT_BUCKET` | obligatoria | `vinculo-vial-audit-<entorno>-<sufijo>`. Igual que en Core. |
| `EVIDENCE_BUCKET`, `S3_REGION` | obligatorias | Bucket de evidencia (solo lectura de `alerts/*/redacted/*`) y región. |
| `MAX_RETRIES` | 10 | Reintentos de un fallo transitorio antes de la DLQ. |
| `RABBITMQ_PREFETCH` | 10 | `basic.qos` de cada consumidor (1 a 65535). |
| `RABBITMQ_PUBLISH_TIMEOUT_MS` | 2000 | Publicación a la DLQ, incluido el confirm. |
| `AUDIT_RECORDED_QUEUE`, `AUDIT_DELIVERED_QUEUE`, `AUDIT_DISCARDED_QUEUE` | ver arriba | Nombres de cola; deben coincidir con Core. |
| `AUDIT_SWEEP_INTERVAL`, `AUDIT_SWEEP_BATCH_SIZE` | `1h`, 500 | Frecuencia del sweeper y tamaño de página. |
| `DB_QUERY_TIMEOUT_MS` | 1500 | Plazo de cada consulta. |
| `S3_PUT_TIMEOUT_MS`, `S3_GET_TIMEOUT_MS` | 5000 | Timeouts de escritura/borrado y de lectura/listado. |
| `S3_MAX_OBJECT_BYTES` | 20971520 | Tope de tamaño de una foto leída. |
| `S3_BREAKER_FAILURE_THRESHOLD`, `S3_BREAKER_WINDOW_MS`, `S3_BREAKER_OPEN_DURATION_MS` | 5, 30000, 30000 | Circuit breaker, uno por bucket. |
| `PORT` | 8080 | `/health`, `/ready` y `/health/deps`. No se publica. |

Las credenciales de AWS salen de la cadena estándar del SDK (variables de entorno en local, rol
IAM en producción).

### Permisos de IAM

- **Bucket de evidencia:** lectura (`s3:GetObject`) de `alerts/*/redacted/*`.
- **Bucket de Audit:** `s3:PutObject`, `s3:GetObject`, `s3:ListBucketVersions`,
  `s3:DeleteObjectVersion`, `s3:PutObjectRetention`, `s3:GetObjectRetention`,
  `s3:PutObjectLegalHold` y `s3:GetObjectLegalHold`.

Sin `s3:ListBucket`, S3 responde 403 en lugar de `NoSuchKey` para un objeto inexistente: es un
requisito del despliegue. El servicio no usa `BypassGovernanceRetention`.

## Sweeper

Cada `AUDIT_SWEEP_INTERVAL` recorre, por páginas, los registros con `destroy_at <= now` y
`judicial_hold = false` (incluidos los `RECORDED` huérfanos, que nunca recibieron su
`discarded`). Para cada uno borra todas las versiones de los objetos de `records/{alert_id}/` y
después la fila. Si S3 rechaza el borrado porque la retención sigue vigente, lo reintenta en la
vuelta siguiente; si la fila falla a mitad de camino, la vuelta siguiente la retoma.

## Ejecución local

```bash
cp .env.example .env            # completar los valores obligatorios
docker network create vinculo-vial   # una vez, si no existe
docker compose up --build
```

El compose levanta el servicio y `audit-db`, sin publicar puertos. El broker y los buckets los
pone el stack (Core).

### Tests

```bash
go test -race ./...                                            # unitarios
DATABASE_URL=... TEST_RABBITMQ_URL=... \
  go test -race -tags integration ./...                        # PostgreSQL y RabbitMQ reales
AUDIT_BUCKET=... S3_REGION=... go test -tags s3 -v ./internal/client/storage/   # opcional, AWS dev
go test -tags smoke -v ./internal/smoke/                       # contra el stack, sin Alert
```

- **Integración:** cada prueba usa su propio esquema de PostgreSQL y colas únicas de RabbitMQ
  (con la topología de retry/DLQ de Core), así que pueden correr en paralelo.
- **`s3`:** prueba opcional contra el bucket de Audit de desarrollo, con `GOVERNANCE` y una
  retención corta. Nunca contra producción.
- **`smoke`:** sube una foto de prueba al bucket de evidencia bajo `alerts/{uuid}/redacted/`,
  publica `recorded` y `delivered`, comprueba que la foto y el manifiesto quedan bloqueados en el
  bucket de Audit y prueba `discarded` sobre otro registro. Requiere el servicio corriendo con
  `GOVERNANCE`; ver las variables en el encabezado del archivo.

## CLIs y procedimiento ante un requerimiento judicial

### `audit-keygen -out <ruta>`

Genera el par X25519. Escribe la clave **privada** (base64, permisos 0600) en `<ruta>`, que debe
estar **fuera de cualquier repositorio** (rechaza una ruta dentro de uno y no sobrescribe), e
imprime la **pública** en stdout: es el valor de `AUDIT_PUBLIC_KEY` en Identity y Vehicle,
junto con un `AUDIT_KEY_ID` (por ejemplo `2026-11`).

### `auditctl export (-alert-id <uuid> | -from <RFC3339> -to <RFC3339>) -out <dir>`

Usa las credenciales de la base (`DATABASE_URL`) y del bucket (`AUDIT_BUCKET`, `S3_REGION`,
credenciales de AWS). Filtra por `alert_id` o por rango de `alert_created_at`; **no hay búsqueda
por DNI ni por patente** (se filtra después de abrir). Por cada registro entregado escribe
`<dir>/<alert_id>/` con `manifest.json`, las fotos y `report.json`. El informe indica:

- si la fila coincide con el manifiesto (y en qué campos difiere);
- si cada foto coincide con su SHA-256;
- si cada objeto tiene la retención esperada (modo de Object Lock vigente hasta `destroy_at`).

Sale con código 3 si encontró alguna diferencia. El directorio de salida no puede estar dentro
de un repositorio. La imagen del servicio incluye `/auditctl`:

```bash
docker run --rm --env-file .env --network vinculo-vial --entrypoint /auditctl \
  vinculo-vial-audit:<tag> export -alert-id <uuid> -out /export
```

(Monte un volumen en `/export` fuera de cualquier repositorio.)

### `auditctl hold -alert-id <uuid> (-on | -off)`

Retención judicial. Marca `judicial_hold` y aplica o quita el legal hold de S3 Object Lock en
**todas las versiones** de los objetos del registro. Mientras está marcado, el sweeper no lo
destruye. Es idempotente: si falla a mitad de camino, repetir el comando completa lo pendiente
(queda siempre del lado seguro).

### `audit-open -in <dir> -out <archivo>`

Corre **fuera de línea** (no importa paquetes de red, base de datos ni AWS; un test lo verifica
con `go list -deps`). Lee las claves privadas por **stdin**, una por línea, en el formato
`audit_key_id=base64`; abre el DNI y la patente de cada manifiesto con su `info` HPKE y escribe
`alert_id`, `dni` y `patente` en `<archivo>` (JSON, permisos 0600, fuera de cualquier
repositorio, no sobrescribe). **Nunca imprime ni loguea los datos**: en stdout solo cantidades.
Sale con código 3 si algún manifiesto no pudo abrirse.

El `info` ata cada criptograma a su alerta y a su campo (`vv-audit:dni:<alert_id>` y
`vv-audit:pat:<alert_id>`): si un criptograma se movió a otro registro, o se intercambiaron el DNI
y la patente, la apertura falla.

### Procedimiento

1. **Recibir el requerimiento** y obtener del responsable legal la identificación de las alertas
   (`alert_id`) o el rango de fechas.
2. **Aplicar la retención judicial** de los registros involucrados, antes de que venzan:
   `auditctl hold -alert-id <uuid> -on`.
3. **Exportar:** `auditctl export … -out <dir>`. Revisar `report.json` de cada registro; si hay
   diferencias (fila alterada, foto alterada, retención insuficiente), documentarlas: son
   evidencia en sí mismas.
4. **Entregar la exportación al responsable legal** por un canal cifrado. La exportación contiene
   los criptogramas y las fotos, pero no el DNI ni la patente en claro.
5. **Abrir fuera de línea**, en un equipo sin red y sin repositorios, con la clave privada en
   manos del responsable legal:
   `audit-open -in <dir> -out <archivo> < claves.txt`, donde cada línea de `claves.txt` es
   `audit_key_id=base64`. Para armar la línea desde el archivo de `audit-keygen`:
   `sed 's/^/2026-11=/' private.key`.
6. **Filtrar por DNI o patente** sobre el archivo abierto, no en Audit.
7. **Destruir** el archivo abierto y la exportación cuando el responsable legal lo indique, y
   quitar la retención judicial cuando corresponda: `auditctl hold … -off`.

**Custodia de la clave privada.** La genera `audit-keygen` fuera de cualquier repositorio y la
custodia el **responsable legal**, fuera de línea. Ningún servicio la carga, ni siquiera Audit.
No existe rotación automática: el formato la admite con `audit_key_id` (los registros viejos se
abren con la clave vieja; `audit-open` acepta varias claves a la vez), pero cambiar de clave es
una operación manual que coordina el responsable legal. Perder la clave privada hace
irrecuperables los datos.

## Seguridad

- Nunca se loguean criptogramas, DNI, patentes, payloads de `audit.*` ni claves de objetos junto
  con datos del registro. Los errores de S3 no reproducen el texto del SDK (que incluye la URL
  con la clave del objeto).
- El mensaje en vuelo de un consumidor no hereda la cancelación del apagado; un panic del
  procesador se captura y deriva el mensaje a la DLQ.
- Imagen mínima (`scratch`), usuario no root, sin shell. `audit-keygen` y `audit-open` no van en
  la imagen del servicio.
- Cada bucket tiene su propio circuit breaker: la degradación de uno no abre el del otro. Con el
  circuito abierto la llamada se rechaza sin alcanzar la red.
- Los criterios OWASP evaluados y los riesgos residuales se detallan en la descripción del PR.
