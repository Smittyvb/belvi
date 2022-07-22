-- SPDX-License-Identifier: Apache-2.0
SELECT log_entries.leaf_hash, log_entries.log_id, log_entries.ts, domains.domain, certs.extra_hash, certs.not_before, certs.not_after
FROM domains
LEFT JOIN log_entries ON log_entries.leaf_hash = domains.leaf_hash
LEFT JOIN certs ON log_entries.leaf_hash = certs.leaf_hash
WHERE domrev(lower(domains.domain)) >= ? AND domrev(lower(domains.domain)) < ?
ORDER BY log_entries.ts DESC -- this is slow when there are a lot of results since a bunch need to be reordered
