CREATE TABLE `User` (
  `id` varchar(36) PRIMARY KEY,
  `username` varchar(255) UNIQUE,
  `email`   varchar(255) UNIQUE NOT NULL,
  `name` varchar(255) NOT NULL,
  `password` varchar(255),
  `role` ENUM ('admin', 'regular') NOT NULL,
  `created_at` datetime NOT NULL,
  `created_by` varchar(36) NOT NULL,
  `updated_at` datetime,
  `updated_by` varchar(36),
  `deleted_at` datetime,
  `deleted_by` varchar(36)
);
