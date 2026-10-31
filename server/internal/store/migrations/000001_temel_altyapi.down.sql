-- Aşama 1 migration'ını geri alır. Denetim kaydını da sildiği için yalnızca geliştirme
-- ortamında kullanılmalıdır; sunucu down migration'ları otomatik çalıştırmaz.
DROP TABLE IF EXISTS audit_log;
DROP FUNCTION IF EXISTS audit_log_immutable();
DROP TABLE IF EXISTS machines;
DROP TABLE IF EXISTS registration_keys;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
