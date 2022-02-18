CREATE TABLE IF NOT EXISTS domains_certs (
    domain TEXT PRIMARY KEY,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    data_hash BLOB NOT NULL
); -- WITH ROWID
