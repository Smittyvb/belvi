// SPDX-License-Identifier: Apache-2.0
function updateDates() {
    const now = new Date();
    document.querySelectorAll("time[datetime]").forEach(ele => {
        let date = new Date(ele.dateTime);
        if (date.getFullYear() === now.getFullYear() && date.getMonth() === now.getMonth() && date.getDate() === now.getDate()) {
            ele.textContent = date.toLocaleTimeString();
        } else {
            ele.textContent = date.toLocaleDateString();
        }
    });
}
window.addEventListener("load", updateDates);
