CREATE TABLE `security_tasks` (
    `id` text PRIMARY KEY NOT NULL,
    `organization_id` text NOT NULL,
    `cipher_id` text,
    `type` integer NOT NULL,
    `status` integer DEFAULT 0 NOT NULL,
    `revision` integer DEFAULT 1 NOT NULL,
    `completed_by_user_id` text,
    `completed_date` text,
    `creation_date` text NOT NULL,
    `revision_date` text NOT NULL,
    FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON UPDATE no action ON DELETE cascade,
    FOREIGN KEY (`cipher_id`) REFERENCES `ciphers`(`id`) ON UPDATE no action ON DELETE cascade,
    FOREIGN KEY (`completed_by_user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX `idx_security_tasks_org_status` ON `security_tasks` (`organization_id`,`status`);
--> statement-breakpoint
CREATE INDEX `idx_security_tasks_cipher` ON `security_tasks` (`cipher_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_security_tasks_pending_org_cipher` ON `security_tasks` (`organization_id`,`cipher_id`) WHERE `status` = 0 AND `cipher_id` IS NOT NULL;
--> statement-breakpoint
DELETE FROM `notifications`
WHERE `task_id` IS NOT NULL
  AND `deleted_date` IS NULL
  AND `rowid` NOT IN (
      SELECT MIN(`rowid`)
      FROM `notifications`
      WHERE `task_id` IS NOT NULL AND `deleted_date` IS NULL
      GROUP BY `user_id`, `task_id`
  );
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_notifications_active_user_task`
ON `notifications` (`user_id`,`task_id`)
WHERE `task_id` IS NOT NULL AND `deleted_date` IS NULL;
