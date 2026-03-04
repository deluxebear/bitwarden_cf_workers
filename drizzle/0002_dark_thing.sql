CREATE TABLE `collection_ciphers` (
	`collection_id` text NOT NULL,
	`cipher_id` text NOT NULL,
	PRIMARY KEY(`collection_id`, `cipher_id`),
	FOREIGN KEY (`collection_id`) REFERENCES `collections`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`cipher_id`) REFERENCES `ciphers`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_coll_ciphers_cipher_id` ON `collection_ciphers` (`cipher_id`);--> statement-breakpoint
CREATE TABLE `collection_users` (
	`collection_id` text NOT NULL,
	`organization_user_id` text NOT NULL,
	`read_only` integer DEFAULT false,
	`hide_passwords` integer DEFAULT false,
	`manage` integer DEFAULT false,
	PRIMARY KEY(`collection_id`, `organization_user_id`),
	FOREIGN KEY (`collection_id`) REFERENCES `collections`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_user_id`) REFERENCES `organization_users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_coll_users_org_user_id` ON `collection_users` (`organization_user_id`);--> statement-breakpoint
CREATE TABLE `collections` (
	`id` text PRIMARY KEY NOT NULL,
	`organization_id` text NOT NULL,
	`name` text NOT NULL,
	`external_id` text,
	`creation_date` text NOT NULL,
	`revision_date` text NOT NULL,
	FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_collections_org_id` ON `collections` (`organization_id`);--> statement-breakpoint
CREATE TABLE `organization_users` (
	`id` text PRIMARY KEY NOT NULL,
	`organization_id` text NOT NULL,
	`user_id` text,
	`email` text NOT NULL,
	`key` text,
	`status` integer DEFAULT 2 NOT NULL,
	`type` integer DEFAULT 2 NOT NULL,
	`permissions` text,
	`creation_date` text NOT NULL,
	`revision_date` text NOT NULL,
	FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_org_users_org_id` ON `organization_users` (`organization_id`);--> statement-breakpoint
CREATE INDEX `idx_org_users_user_id` ON `organization_users` (`user_id`);--> statement-breakpoint
CREATE TABLE `organizations` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`billing_email` text NOT NULL,
	`email` text,
	`key` text,
	`plan_type` integer DEFAULT 0,
	`seats` integer DEFAULT 5,
	`max_storage_gb` integer DEFAULT 1,
	`use_totp` integer DEFAULT false,
	`use_web_authn` integer DEFAULT false,
	`enabled` integer DEFAULT true,
	`creation_date` text NOT NULL,
	`revision_date` text NOT NULL
);
