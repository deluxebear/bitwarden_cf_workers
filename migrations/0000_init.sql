CREATE TABLE `ciphers` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text,
	`organization_id` text,
	`type` integer NOT NULL,
	`data` text NOT NULL,
	`favorites` text,
	`folders` text,
	`attachments` text,
	`reprompt` integer DEFAULT 0,
	`key` text,
	`creation_date` text NOT NULL,
	`revision_date` text NOT NULL,
	`deleted_date` text,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_ciphers_user_id` ON `ciphers` (`user_id`);--> statement-breakpoint
CREATE INDEX `idx_ciphers_organization_id` ON `ciphers` (`organization_id`);--> statement-breakpoint
CREATE TABLE `devices` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`name` text NOT NULL,
	`type` integer NOT NULL,
	`identifier` text NOT NULL,
	`push_token` text,
	`encrypted_user_key` text,
	`encrypted_public_key` text,
	`encrypted_private_key` text,
	`active` integer DEFAULT true NOT NULL,
	`creation_date` text NOT NULL,
	`revision_date` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_devices_user_id` ON `devices` (`user_id`);--> statement-breakpoint
CREATE INDEX `idx_devices_identifier` ON `devices` (`identifier`);--> statement-breakpoint
CREATE TABLE `folders` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`name` text,
	`creation_date` text NOT NULL,
	`revision_date` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_folders_user_id` ON `folders` (`user_id`);--> statement-breakpoint
CREATE TABLE `refresh_tokens` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`device_id` text,
	`token_hash` text NOT NULL,
	`expiration_date` text NOT NULL,
	`creation_date` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`device_id`) REFERENCES `devices`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_refresh_tokens_user_id` ON `refresh_tokens` (`user_id`);--> statement-breakpoint
CREATE INDEX `idx_refresh_tokens_token_hash` ON `refresh_tokens` (`token_hash`);--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text,
	`email` text NOT NULL,
	`email_verified` integer DEFAULT false NOT NULL,
	`master_password` text,
	`master_password_hint` text,
	`culture` text DEFAULT 'en-US' NOT NULL,
	`security_stamp` text NOT NULL,
	`two_factor_providers` text,
	`two_factor_recovery_code` text,
	`equivalent_domains` text,
	`excluded_global_equivalent_domains` text,
	`account_revision_date` text NOT NULL,
	`key` text,
	`public_key` text,
	`private_key` text,
	`signed_public_key` text,
	`kdf` integer DEFAULT 0 NOT NULL,
	`kdf_iterations` integer DEFAULT 600000 NOT NULL,
	`kdf_memory` integer,
	`kdf_parallelism` integer,
	`premium` integer DEFAULT false NOT NULL,
	`force_password_reset` integer DEFAULT false NOT NULL,
	`uses_key_connector` integer DEFAULT false NOT NULL,
	`failed_login_count` integer DEFAULT 0 NOT NULL,
	`last_failed_login_date` text,
	`avatar_color` text,
	`api_key` text NOT NULL,
	`creation_date` text NOT NULL,
	`revision_date` text NOT NULL,
	`last_password_change_date` text,
	`last_kdf_change_date` text,
	`last_key_rotation_date` text,
	`last_email_change_date` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_email_unique` ON `users` (`email`);