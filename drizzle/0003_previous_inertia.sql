CREATE TABLE `events` (
	`id` text PRIMARY KEY NOT NULL,
	`type` integer NOT NULL,
	`user_id` text,
	`organization_id` text,
	`cipher_id` text,
	`collection_id` text,
	`acting_user_id` text,
	`date` text NOT NULL,
	`device_type` integer,
	`ip_address` text,
	`system_user` integer
);
