CREATE TABLE IF NOT EXISTS `policies` (
	`id` text PRIMARY KEY NOT NULL,
	`organization_id` text NOT NULL REFERENCES `organizations`(`id`) ON DELETE CASCADE,
	`type` integer NOT NULL,
	`data` text,
	`enabled` integer DEFAULT false NOT NULL,
	`creation_date` text NOT NULL,
	`revision_date` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_policies_organization_id` ON `policies` (`organization_id`);
