CREATE TABLE IF NOT EXISTS `notifications` (
    `id` text PRIMARY KEY NOT NULL,
    `user_id` text NOT NULL,
    `organization_id` text,
    `priority` integer DEFAULT 0 NOT NULL,
    `global` integer DEFAULT false NOT NULL,
    `client_type` integer DEFAULT 0 NOT NULL,
    `title` text,
    `body` text,
    `task_id` text,
    `data` text,
    `read_date` text,
    `deleted_date` text,
    `creation_date` text NOT NULL,
    `revision_date` text NOT NULL,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_notifications_user_id` ON `notifications` (`user_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_notifications_org_id` ON `notifications` (`organization_id`);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_notifications_revision_date` ON `notifications` (`revision_date`);
