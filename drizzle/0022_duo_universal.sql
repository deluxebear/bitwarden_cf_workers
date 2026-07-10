CREATE TABLE `duo_configs` (
    `id` text PRIMARY KEY NOT NULL,
    `user_id` text REFERENCES `users`(`id`) ON DELETE cascade,
    `organization_id` text REFERENCES `organizations`(`id`) ON DELETE cascade,
    `client_id` text NOT NULL,
    `host` text NOT NULL,
    `client_secret_ciphertext` text NOT NULL,
    `client_secret_iv` text NOT NULL,
    `client_secret_prefix` text NOT NULL,
    `key_version` integer DEFAULT 1 NOT NULL,
    `creation_date` text NOT NULL,
    `revision_date` text NOT NULL,
    CONSTRAINT `duo_configs_one_owner` CHECK (
        (`user_id` IS NOT NULL AND `organization_id` IS NULL) OR
        (`user_id` IS NULL AND `organization_id` IS NOT NULL)
    )
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_duo_configs_user_id`
ON `duo_configs` (`user_id`) WHERE `user_id` IS NOT NULL;
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_duo_configs_organization_id`
ON `duo_configs` (`organization_id`) WHERE `organization_id` IS NOT NULL;
--> statement-breakpoint
CREATE TABLE `duo_login_states` (
    `state_hash` text PRIMARY KEY NOT NULL,
    `user_id` text NOT NULL REFERENCES `users`(`id`) ON DELETE cascade,
    `provider_type` integer NOT NULL CHECK (`provider_type` IN (2, 6)),
    `organization_id` text REFERENCES `organizations`(`id`) ON DELETE cascade,
    `config_id` text NOT NULL REFERENCES `duo_configs`(`id`) ON DELETE cascade,
    `config_revision` text NOT NULL,
    `nonce` text NOT NULL,
    `redirect_uri` text NOT NULL,
    `creation_date` text NOT NULL,
    `expiration_date` text NOT NULL,
    `consumed_date` text,
    CONSTRAINT `duo_login_states_provider_owner` CHECK (
        (`provider_type` = 2 AND `organization_id` IS NULL) OR
        (`provider_type` = 6 AND `organization_id` IS NOT NULL)
    )
);
--> statement-breakpoint
CREATE INDEX `idx_duo_login_states_user`
ON `duo_login_states` (`user_id`, `provider_type`);
--> statement-breakpoint
CREATE INDEX `idx_duo_login_states_expiration`
ON `duo_login_states` (`expiration_date`);
