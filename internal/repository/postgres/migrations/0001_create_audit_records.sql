-- Registro de auditoría de cada alerta que llegó a un destinatario (US-11).
-- Los criptogramas se guardan tal como llegan: Audit nunca los descifra.
CREATE TABLE audit_records (
    alert_id         uuid         PRIMARY KEY,
    alert_type       varchar(32)  NOT NULL,
    alert_created_at timestamptz  NOT NULL,
    dni_enc_audit    text         NOT NULL,
    pat_enc_audit    text         NOT NULL,
    audit_key_id     varchar(32)  NOT NULL,
    status           varchar(16)  NOT NULL CHECK (status IN ('RECORDED', 'DELIVERED')),
    recorded_at      timestamptz  NOT NULL,
    delivered_at     timestamptz,
    evidence         jsonb,
    manifest_key     text,
    manifest_sha256  varchar(64),
    destroy_at       timestamptz  NOT NULL,
    judicial_hold    boolean      NOT NULL DEFAULT false
);

CREATE INDEX idx_audit_records_alert_created_at ON audit_records (alert_created_at);
CREATE INDEX idx_audit_records_destroy_at ON audit_records (destroy_at);

-- Inmutabilidad: una vez insertado, el registro no cambia sus datos de origen.
-- Solo pueden actualizarse el estado de entrega (status, delivered_at, evidence,
-- manifest_key, manifest_sha256) y judicial_hold.
CREATE FUNCTION audit_records_forbid_origin_update() RETURNS trigger AS $$
BEGIN
    IF NEW.alert_id         IS DISTINCT FROM OLD.alert_id
    OR NEW.alert_type       IS DISTINCT FROM OLD.alert_type
    OR NEW.alert_created_at IS DISTINCT FROM OLD.alert_created_at
    OR NEW.dni_enc_audit    IS DISTINCT FROM OLD.dni_enc_audit
    OR NEW.pat_enc_audit    IS DISTINCT FROM OLD.pat_enc_audit
    OR NEW.audit_key_id     IS DISTINCT FROM OLD.audit_key_id
    OR NEW.recorded_at      IS DISTINCT FROM OLD.recorded_at
    OR NEW.destroy_at       IS DISTINCT FROM OLD.destroy_at THEN
        RAISE EXCEPTION 'audit_records: los datos de origen del registro son inmutables';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_records_immutable_origin
    BEFORE UPDATE ON audit_records
    FOR EACH ROW EXECUTE FUNCTION audit_records_forbid_origin_update();
