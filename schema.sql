-- schema.sql
-- MySQL / MariaDB schema for SpoofShield scan history
CREATE TABLE IF NOT EXISTS `scan_history` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `investigation_id` VARCHAR(64) NOT NULL UNIQUE,
  `target` VARCHAR(255) DEFAULT NULL,
  `type` VARCHAR(50) NOT NULL DEFAULT 'dns',
  `scanned_at` DATETIME NOT NULL,
  `records` JSON DEFAULT NULL,
  `risk_score` TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `risk_level` VARCHAR(20) DEFAULT 'Low',
  `findings` JSON DEFAULT NULL,
  `limitations` JSON DEFAULT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX (`scanned_at`),
  INDEX (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
