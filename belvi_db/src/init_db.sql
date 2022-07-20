-- SPDX-License-Identifier: Apache-2.0
-- Run every time the SQLite database is loaded.

-- CONFIGURE SQLITE --
PRAGMA journal_mode = WAL;
PRAGMA encoding = 'UTF-8';
PRAGMA user_version = 1;
PRAGMA synchronous = NORMAL;

BEGIN;

-- INITALIZE TABLES --
-- once SQLite 3.37 (2021-11-27) is more widely deployed, make these strict tables
CREATE TABLE IF NOT EXISTS meta(
    k TEXT PRIMARY KEY,
    v TEXT
); -- WITH ROWID
-- if schema is changed in future, an actual system for migrating the DB will be implemented
-- for now, just assume we are always on the initial version
INSERT OR REPLACE into meta (k, v) values ("migration", "1.0.0");
CREATE TABLE IF NOT EXISTS certs (
    leaf_hash BLOB PRIMARY KEY NOT NULL, -- SHA256 of leaf data
    extra_hash BLOB NOT NULL, -- SHA256 of extra data
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    cert_type NUMBER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS log_entries (
    leaf_hash BLOB NOT NULL, -- SHA256 of leaf data
    log_id NUMBER NOT NULL, -- ID of log
    idx NUMBER NOT NULL, -- index in log
    ts NUMBER NOT NULL, -- time the certificate was incorporated into the first log we saw this cert in
    PRIMARY KEY (leaf_hash, log_id)
);
CREATE TABLE IF NOT EXISTS domains (
    -- TODO: also store reverse of domain to make *.com queries possible with < and >
    domain TEXT NOT NULL, -- normalized FQDN without trailing .
    leaf_hash BLOB NOT NULL, -- SHA256 of leaf data
    PRIMARY KEY (domain, leaf_hash),
    FOREIGN KEY (leaf_hash) REFERENCES log_entries(leaf_hash)
); -- WITH ROWID

-- CREATE INDICIES --
CREATE INDEX IF NOT EXISTS idx_domains_domain1 ON domains (domain);
CREATE INDEX IF NOT EXISTS idx_domains_leaf_hash1 ON domains (leaf_hash);
CREATE INDEX IF NOT EXISTS idx_log_entries_ts1 ON log_entries (ts);

COMMIT;

-- OPTIMIZE DB --
PRAGMA optimize;
