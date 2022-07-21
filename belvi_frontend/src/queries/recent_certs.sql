-- SPDX-License-Identifier: Apache-2.0
SELECT log_entries_leaf_hash AS leaf_hash, log_id, ts, domain, extra_hash, not_before, not_after
FROM (
    SELECT log_entries.leaf_hash AS log_entries_leaf_hash, log_entries.log_id, log_entries.ts, certs.extra_hash, certs.not_before, certs.not_after
    FROM log_entries
    LEFT JOIN certs ON log_entries.leaf_hash = certs.leaf_hash
    ORDER BY log_entries.ts DESC
)
LEFT JOIN domains ON log_entries_leaf_hash = domains.leaf_hash
ORDER BY ts DESC
