CREATE TABLE `sends` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text,
	`organization_id` text,
	`type` integer NOT NULL,
	`data` text,
	`key` text,
	`password` text,
	`max_access_count` integer,
	`access_count` integer DEFAULT 0 NOT NULL,
	`expiration_date` text,
	`deletion_date` text NOT NULL,
	`disabled` integer DEFAULT false NOT NULL,
	`hide_email` integer DEFAULT false,
	`creation_date` text NOT NULL,
	`revision_date` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_sends_user_id` ON `sends` (`user_id`);