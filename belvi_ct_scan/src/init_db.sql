-- Run every time the SQLite database is loaded.

-- INITALIZE TABLES --

CREATE TABLE IF NOT EXISTS meta(
    k TEXT PRIMARY KEY,
    v TEXT
);

-- if schema is changed in future, an actual system for migrating the DB will be implemented
-- for now, just assume we are always on the initial version
INSERT OR REPLACE into meta (k, v) values ("migration", "1.0.0");

CREATE TABLE IF NOT EXISTS domain_certs (
    domain TEXT PRIMARY KEY, -- indexed because primary key
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    data_hash BLOB NOT NULL
); -- WITH ROWID

-- CONFIGURE SQLITE --
PRAGMA journal_mode = WAL;
PRAGMA encoding = 'UTF-8';
PRAGMA user_version = 1;

-- OPTIMIZE DB --
PRAGMA optimize;
VACUUM;
