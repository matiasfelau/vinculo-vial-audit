// Package postgrestest provee una base PostgreSQL aislada por prueba para las
// pruebas de integración (build tag integration). Cada prueba obtiene su propio
// esquema, migrado con las migraciones reales, y lo destruye al terminar: los
// paquetes de prueba pueden correr en paralelo contra la misma instancia sin
// pisarse.
package postgrestest
