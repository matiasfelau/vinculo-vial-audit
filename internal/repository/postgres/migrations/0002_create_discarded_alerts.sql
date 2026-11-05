-- Tombstones de descartes (US-11). Con entrega al menos una vez, un discarded
-- duplicado llega después de borrado el registro, y un recorded duplicado puede
-- llegar después del descarte: sin esta tabla uno terminaría en la DLQ y el otro
-- recrearía un registro con DNI que nadie borraría hasta su vencimiento.
-- No guarda datos personales: solo el alert_id y cuándo se descartó. El sweeper
-- la depura pasados AUDIT_TOMBSTONE_DAYS.
CREATE TABLE discarded_alerts (
    alert_id     uuid        PRIMARY KEY,
    discarded_at timestamptz NOT NULL
);

CREATE INDEX idx_discarded_alerts_discarded_at ON discarded_alerts (discarded_at);
