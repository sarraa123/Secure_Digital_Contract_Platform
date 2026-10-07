/**
 * Modale de confirmation personnalisée.
 * Remplace window.confirm() et window.alert() par des modales Veridoc.
 */
(function () {
    "use strict";

    // =====================================================================
    //  SHOW CONFIRM — 2 boutons (Confirmer / Annuler)
    // =====================================================================
    window.showConfirm = function (options) {
        return new Promise((resolve) => {
            const {
                title = "Confirmer",
                message = "Êtes-vous sûr ?",
                confirmLabel = "Confirmer",
                cancelLabel = "Annuler",
                variant = "primary",
            } = options || {};

            const overlay = document.createElement("div");
            overlay.className = "confirm-overlay";

            overlay.innerHTML = `
                <div class="confirm-modal">
                    <div class="confirm-modal-head">
                        <h3>${escapeHtml(title)}</h3>
                    </div>
                    <div class="confirm-modal-body">
                        <p>${escapeHtml(message)}</p>
                    </div>
                    <div class="confirm-modal-actions">
                        <button type="button" class="confirm-btn cancel">
                            ${escapeHtml(cancelLabel)}
                        </button>
                        <button type="button" class="confirm-btn ${variant}">
                            ${escapeHtml(confirmLabel)}
                        </button>
                    </div>
                </div>
            `;

            document.body.appendChild(overlay);
            requestAnimationFrame(() => overlay.classList.add("open"));

            const close = (result) => {
                overlay.classList.remove("open");
                setTimeout(() => {
                    overlay.remove();
                    resolve(result);
                }, 200);
            };

            overlay.querySelector(".confirm-btn.cancel")
                   .addEventListener("click", () => close(false));
            overlay.querySelector(".confirm-btn." + variant)
                   .addEventListener("click", () => close(true));
            overlay.addEventListener("click", (e) => {
                if (e.target === overlay) close(false);
            });

            const onKey = (e) => {
                if (e.key === "Escape") {
                    document.removeEventListener("keydown", onKey);
                    close(false);
                }
            };
            document.addEventListener("keydown", onKey);
        });
    };

    // =====================================================================
    //  SHOW ALERT — 1 bouton (OK)
    // =====================================================================
    window.showAlert = function (options) {
        return new Promise((resolve) => {
            const {
                title = "Information",
                message = "",
                buttonLabel = "OK",
                variant = "primary",
            } = options || {};

            const overlay = document.createElement("div");
            overlay.className = "confirm-overlay";

            overlay.innerHTML = `
                <div class="confirm-modal">
                    <div class="confirm-modal-head">
                        <h3>${escapeHtml(title)}</h3>
                    </div>
                    <div class="confirm-modal-body">
                        <p>${escapeHtml(message)}</p>
                    </div>
                    <div class="confirm-modal-actions">
                        <button type="button" class="confirm-btn ${variant}">
                            ${escapeHtml(buttonLabel)}
                        </button>
                    </div>
                </div>
            `;

            document.body.appendChild(overlay);
            requestAnimationFrame(() => overlay.classList.add("open"));

            const close = () => {
                overlay.classList.remove("open");
                setTimeout(() => {
                    overlay.remove();
                    resolve();
                }, 200);
            };

            overlay.querySelector(".confirm-btn." + variant)
                   .addEventListener("click", close);
            overlay.addEventListener("click", (e) => {
                if (e.target === overlay) close();
            });

            const onKey = (e) => {
                if (e.key === "Escape" || e.key === "Enter") {
                    document.removeEventListener("keydown", onKey);
                    close();
                }
            };
            document.addEventListener("keydown", onKey);
        });
    };

    // =====================================================================
    //  Utilitaires
    // =====================================================================
    function escapeHtml(s) {
        return String(s || "").replace(/[&<>"']/g, c => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;",
            '"': "&quot;", "'": "&#39;"
        }[c]));
    }
})();