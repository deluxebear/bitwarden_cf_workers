CREATE TABLE `organization_licenses` (
	`organization_id` text PRIMARY KEY NOT NULL,
	`license_key` text NOT NULL,
	`license_json` text NOT NULL,
	`issued` text,
	`expires` text,
	`self_host` integer,
	`installation_id` text,
	`creation_date` text NOT NULL,
	`revision_date` text NOT NULL,
	FOREIGN KEY (`organization_id`) REFERENCES `organizations`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_org_licenses_license_key` ON `organization_licenses` (`license_key`);

