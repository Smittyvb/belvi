// SPDX-License-Identifier: Apache-2.0
window.addEventListener("load", () => {
    document.querySelectorAll(".bvcert-bytes[data-full]").forEach(ele => {
        const handler = event => {
            ele.removeEventListener("click", handler);
            ele.classList.add("bvcert-expanded-bytes");
            ele.textContent = ele.dataset.full;
            ele.style.cursor = "inherit";
        };
        ele.addEventListener("click", handler);
        ele.style.cursor = "pointer";
    });
});
