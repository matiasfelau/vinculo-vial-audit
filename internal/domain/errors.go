package domain

import "errors"

var (
	// ErrRecordNotFound indica que no existe el registro de la alerta. Para los
	// consumidores es transitorio: delivered o discarded pueden llegar antes que
	// recorded.
	ErrRecordNotFound = errors.New("domain: registro de auditoría inexistente")

	// ErrRepositoryUnavailable indica que la base propia es inalcanzable o que una
	// consulta excedió su plazo. Es transitorio.
	ErrRepositoryUnavailable = errors.New("domain: no se pudo consultar la base de datos")

	// ErrStorageUnavailable indica que S3 es inalcanzable, excedió su plazo o tiene
	// el circuito abierto. Es transitorio.
	ErrStorageUnavailable = errors.New("domain: almacenamiento no disponible")

	// ErrStorageRejected indica que S3 respondió con un 4xx distinto de not found
	// (por ejemplo, permisos). No cuenta para el circuit breaker; el consumidor lo
	// reintenta hasta MAX_RETRIES para dar tiempo a corregir el despliegue.
	ErrStorageRejected = errors.New("domain: el almacenamiento rechazó la operación")

	// ErrObjectNotFound indica que el objeto pedido no existe.
	ErrObjectNotFound = errors.New("domain: objeto inexistente")

	// ErrObjectTooLarge indica que un objeto excede el tope de tamaño admitido.
	ErrObjectTooLarge = errors.New("domain: el objeto excede el tamaño máximo")

	// ErrRetentionActive indica que S3 rechazó un borrado porque la retención o el
	// legal hold del objeto siguen vigentes. El sweeper lo reintenta en la vuelta
	// siguiente.
	ErrRetentionActive = errors.New("domain: la retención del objeto sigue vigente")

	// ErrIntegrity indica que el contenido de una foto no coincide con el SHA-256
	// declarado en el evento. Es permanente.
	ErrIntegrity = errors.New("domain: el contenido de la foto no coincide con su SHA-256")

	// ErrRetentionElapsed indica que destroy_at ya pasó: S3 no admite una retención
	// en el pasado. Es permanente.
	ErrRetentionElapsed = errors.New("domain: la fecha de destrucción del registro ya venció")

	// ErrAlertDiscarded indica que la alerta ya fue descartada (existe su tombstone) y
	// llegó un evento que presupone un registro vivo, como delivered. Es una
	// inconsistencia de Alert: permanente.
	ErrAlertDiscarded = errors.New("domain: la alerta ya fue descartada")
)
