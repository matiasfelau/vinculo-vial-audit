// Package events implementa el consumo de eventos de auditoría desde RabbitMQ.
// La topología (exchanges, colas de trabajo, .retry y .dlq) la declara solo
// vinculo-vial-core: este servicio consume sobre topología existente y nunca
// publica eventos propios; únicamente deriva a la DLQ los mensajes que no puede
// procesar.
package events

import (
	"log/slog"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	reconnectInitialDelay = 1 * time.Second
	reconnectMaxDelay     = 30 * time.Second
)

// watchReturns loguea en WARN cada mensaje que el broker devuelve por no poder
// enrutarlo (mandatory=true sin cola destino). Nunca incluye el cuerpo del
// mensaje. Termina cuando el canal se cierra, así que se lanza una vez por canal.
func watchReturns(returns <-chan amqp.Return) {
	for ret := range returns {
		slog.Warn("rabbitmq: mensaje no enrutable, el broker lo devolvió",
			"exchange", ret.Exchange,
			"routing_key", ret.RoutingKey,
			"reply_code", ret.ReplyCode,
			"reply_text", ret.ReplyText,
		)
	}
}
