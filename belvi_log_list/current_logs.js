// SPDX-License-Identifier: Apache-2.0
// Determines what logs are current. Current logs possibly contain certificates that are currently valid.

const https = require("https");
const util = require("util");
const data = require("./log_list.json");

const now = new Date();

function unexpiredCertsIssuedBeforeDate(date) {
    // https://source.chromium.org/chromium/chromium/src/+/main:net/cert/cert_verify_proc.cc;l=894    
    // all pre-BR certs should have expired by now
    // 1 July 2012 to 01 April 2015: 60 months, all have expired
    // 01 April 2015 to 1 March 2018: 39 months, all have expired
    // 1 March 2018 to 1 September 2020: 825 days
    // 1 September 2020 to present: 398 days
    // thus, the oldest unexpired certs are 825 days old, until late 2022
    const daysAgo = (date - now) / 86400000;
    return daysAgo > 825;
}

function isCurrent(log) {
    // we don't account for expiration date
    if (log.temporal_interval) {
        const end = new Date(log.temporal_interval.end_exclusive);
        if (now > end) return false;
    }
    if (log.state.retired) {
        if (!unexpiredCertsIssuedBeforeDate(new Date(log.state.retired.timestamp))) return false;;
    }
    if (log.state.readonly) {
        if (!unexpiredCertsIssuedBeforeDate(new Date(log.state.readonly.timestamp))) return false;;
    }
    return true;
}

const logs = [].concat.apply([], data.operators.map(op => op.logs));
const curLogs = logs.filter(e => isCurrent(e));
console.log(logs.length, curLogs.length, curLogs.map(l => l.description));

(async () => {
    let total = 0;
    for (let log of curLogs) {
        const sthUri = log.url + "ct/v1/get-sth";
        await new Promise(resolve => https.get(sthUri, res => {
            let body = "";
            res.on("data", chunk => body += chunk);
            res.on("end", () => {
                const data = JSON.parse(body);
                console.log(log.description, data.tree_size.toLocaleString());
                total += data.tree_size;
                resolve();
            });
        }));
    }
    console.log("Total", total.toLocaleString());
    // feb 2022: ~6 billion total, ~4 billion in Google logs
})();
