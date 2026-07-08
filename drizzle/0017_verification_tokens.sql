CREATE TABLE IF NOT EXISTS `verification_tokens` (
    `id` text PRIMARY KEY NOT NULL,
    `user_id` text,
    `email` text NOT NULL,
    `type` text NOT NULL,
    `token_hash` text NOT NULL,
    `expires_at` text NOT NULL,
    `used_at` text,
    `creation_date` text NOT NULL,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_verification_tokens_email_type` ON `verification_tokens` (`email`,`type`);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `idx_verification_tokens_hash` ON `verification_tokens` (`token_hash`);
