CREATE TABLE IF NOT EXISTS `emergency_access` (
    `id` text PRIMARY KEY NOT NULL,
    `grantor_id` text NOT NULL,
    `grantee_id` text,
    `email` text,
    `key_encrypted` text,
    `type` integer NOT NULL,
    `status` integer NOT NULL,
    `wait_time_days` integer NOT NULL,
    `recovery_initiated_date` text,
    `recovery_rejected_date` text,
    `last_notification_date` text,
    `revoked_date` text,
    `revoked_by_user_id` text,
    `creation_date` text NOT NULL,
    `revision_date` text NOT NULL,
    FOREIGN KEY (`grantor_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
    FOREIGN KEY (`grantee_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
    FOREIGN KEY (`revoked_by_user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null,
    CHECK (`type` IN (0, 1)),
    CHECK (`status` BETWEEN 0 AND 4),
    CHECK (`wait_time_days` BETWEEN 0 AND 365),
    CHECK ((`status` = 0 AND `email` IS NOT NULL AND `grantee_id` IS NULL) OR
           (`status` > 0 AND `email` IS NULL AND `grantee_id` IS NOT NULL))
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_emergency_access_grantor_id` ON `emergency_access` (`grantor_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_emergency_access_grantee_id` ON `emergency_access` (`grantee_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_emergency_access_email` ON `emergency_access` (`email`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_emergency_access_status` ON `emergency_access` (`status`);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `idx_emergency_access_active_grantor_email`
    ON `emergency_access` (`grantor_id`, `email`) WHERE `revoked_date` IS NULL AND `email` IS NOT NULL;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `idx_emergency_access_active_grantor_grantee`
    ON `emergency_access` (`grantor_id`, `grantee_id`) WHERE `revoked_date` IS NULL AND `grantee_id` IS NOT NULL;
