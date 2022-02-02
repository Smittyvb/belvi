<!-- SPDX-License-Identifier: Apache-2.0 -->
# scanlog_wrangler

This manages invokations of the `scanlog` binary of [certificate-transparency-go](https://github.com/google/certificate-transparency-go) to maintain a complete history of certificates across multiple logs. Unlike `scanlog` itself, `scanlog_wrangler` can resume if it is stopped without needing to fetch all certificates from scratch again. Once all certificates are obtained for a log, `scanlog_wrangler` periodically fetches any new certificates that may have been added to the log.

If this is used to manage a significant number of certificates, you may wish to store them on a compressed file system (such as ZFS).
