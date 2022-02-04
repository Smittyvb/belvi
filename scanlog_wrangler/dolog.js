// SPDX-License-Identifier: Apache-2.0
const { spawn } = require("child_process");
const fs = require("fs");
const https = require("https");
const assert = require("assert").strict;

const STRIDE = 20000;

(async () => {
    // setup

    const scanlogPath = process.argv[2];
    const logUrl = process.argv[3];
    const certsPath = process.argv[4];
    const logId = process.argv[5];
    if (!scanlogPath || !logUrl || !certsPath || !logId) {
        throw new Error("not all inputs specified");
    }

    const logPath = `${certsPath}/${logId}`;
    const logMetaPath = `${certsPath}/${logId}.json`;
    if (!fs.existsSync(logPath)) {
        fs.mkdirSync(logPath, { recursive: true });
    }

    let meta;
    if (fs.existsSync(logMetaPath)) {
        meta = JSON.parse(fs.readFileSync(logMetaPath, "utf-8"));
    } else {
        meta = { idx: 0 };
        metaChanged();
    }
    function metaChanged() {
        fs.writeFileSync(logMetaPath, JSON.stringify(meta), "utf-8");
    }

    const sthUri = logUrl + "/ct/v1/get-sth";
    let sth;
    await new Promise(resolve => https.get(sthUri, res => {
        let body = "";
        res.on("data", chunk => body += chunk);
        res.on("end", () => {
            const data = JSON.parse(body);
            sth = data;
            resolve();
        });
    }));
    if (meta.last_sth) {
        if (sth.tree_size > meta.last_sth.tree_size) {
            console.warn("CT log truncated", meta.last_sth, sth);
            throw new Error("CT log is broken");
        }
        if (sth.tree_size === meta.idx) {
            console.log("No certs appended since last check");
            return;
        }
    }
    meta.last_sth = sth;

    const certCount = fs.readdirSync(logPath).length;
    assert((certCount >= meta.idx) && (certCount <= (meta.idx + STRIDE)), "current total certs must be meta.idx or meta.idx plus some certs within the current stride");

    // fetch certs

    console.log("Initialized, starting fetching");
    while (meta.idx < sth.tree_size) {
        const start = Date.now();
        await new Promise((resolve, reject) => {
            const cmd = spawn(
                scanlogPath,
                [
                    "-log_uri",
                    logUrl,
                    
                    "-dump_dir",
                    logPath,

                    "-start_index", // inclusive
                    meta.idx.toString(), // meta.idx points to next certificate to fetch

                    "-end_index", // exclusive
                    (meta.idx + STRIDE).toString(),

                    "-batch_size",
                    "100",

                    "-parallel_fetch",
                    "4",

                    "-dump_full_chain=false",
                ],
            );
            cmd.stdout.pipe(process.stdout);
            cmd.stderr.pipe(process.stderr);
            cmd.on("close", code => {
                if (code === 0) resolve();
                reject(`Bad exit code ${code}`);
            });
        });
        const end = Date.now();
        const duration = end - start;
        const certCount = fs.readdirSync(logPath).length;
        assert.equal(certCount, meta.idx + STRIDE);    
        meta.idx += STRIDE;
        metaChanged();
        console.log(`Fetched ${STRIDE} certs in ${(duration / 1000).toFixed(1)}s, ${(duration / STRIDE).toFixed(1)}ms per cert`);
    }
    console.log("Caught up to CT log");
})();
