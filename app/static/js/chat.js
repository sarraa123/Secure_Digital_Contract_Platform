/**
 * Chat temps réel par contrat + bouton "Finaliser" + "Demander une modification"
 * + upload PDF.
 */
(function () {
    "use strict";

    const config = document.getElementById("chat-config");
    if (!config) return;

    const CONTRACT_ID = parseInt(config.dataset.contractId, 10);
    const USER_ID     = parseInt(config.dataset.userId, 10);
    const USER_NAME   = config.dataset.userName || "Vous";
    const CHAT_LOCKED = config.dataset.locked === "true";

    if (!CONTRACT_ID || !USER_ID) return;

    // --- DOM
    const fab         = document.getElementById("chat-fab");
    const panel       = document.getElementById("chat-panel");
    const closeBtn    = document.getElementById("chat-close");
    const msgList     = document.getElementById("chat-messages");
    const typingEl    = document.getElementById("chat-typing");
    const inputForm   = document.getElementById("chat-input");
    const textarea    = document.getElementById("chat-textarea");
    const sendBtn     = document.getElementById("chat-send");
    const badge       = document.getElementById("chat-fab-badge");
    const iaResult    = document.getElementById("chat-ia-result");
    const btnFinalize = document.getElementById("btn-finalize");
    const attachBtn   = document.getElementById("chat-attach-btn");
    const pdfInput    = document.getElementById("chat-pdf-input");
    const btnRequest  = document.getElementById("btn-request-amendment");

    if (!panel || !msgList) return;

    // =====================================================================
    //  Socket.IO
    // =====================================================================
    let socket = null;
    if (typeof io === "function") {
        socket = io({ transports: ["websocket", "polling"] });

        socket.on("connect", () => {
            console.log("[chat] connecté", socket.id);
            socket.emit("join_chat", { contract_id: CONTRACT_ID });
        });

        socket.on("new_message", (data) => {
            if (data.contract_id !== CONTRACT_ID) return;
            appendMessage(data);
        });

        socket.on("user_typing", (data) => {
            if (data.user_id === USER_ID) return;
            showTyping(data);
        });

        socket.on("error", (data) => {
            console.error("[chat] erreur", data);
        });
    }

    // =====================================================================
    //  Ouverture / fermeture
    // =====================================================================
    function openChat() {
        panel.classList.add("open");
        loadMessages();
        markAllRead();
        if (socket) socket.emit("join_chat", { contract_id: CONTRACT_ID });
    }

    function closeChat() {
        panel.classList.remove("open");
        if (socket) socket.emit("leave_chat", { contract_id: CONTRACT_ID });
    }

    if (fab)      fab.addEventListener("click", openChat);
    if (closeBtn) closeBtn.addEventListener("click", closeChat);

    // =====================================================================
    //  Chargement des messages
    // =====================================================================
    async function loadMessages() {
        try {
            const r = await fetch(`/api/contracts/${CONTRACT_ID}/messages`, {
                headers: { "Accept": "application/json" },
                credentials: "same-origin"
            });
            if (!r.ok) return;
            const data = await r.json();
            if (!data.ok) return;

            msgList.innerHTML = "";

            if (!data.messages || data.messages.length === 0) {
                msgList.innerHTML =
                    '<div class="chat-empty">Aucun message pour le moment.<br>Commencez la discussion.</div>';
                return;
            }

            data.messages.forEach(appendMessage);
            msgList.scrollTop = msgList.scrollHeight;

        } catch (e) {
            console.error("[chat] load error", e);
        }
    }

    // =====================================================================
    //  Ajout d'un message
    // =====================================================================
    function appendMessage(msg) {
        if (msg.message_type === "pdf") {
            appendPdfMessage({
                id:          msg.id,
                sender_id:   msg.sender_id,
                sender_name: msg.sender_name,
                filename:    msg.attachment_filename,
                created_at:  msg.created_at,
            });
            return;
        }

        const empty = msgList.querySelector(".chat-empty");
        if (empty) empty.remove();

        if (msg.id && msgList.querySelector(`[data-msg-id="${msg.id}"]`)) return;

        const isMe = parseInt(msg.sender_id, 10) === USER_ID;
        const isSystem = msg.sender_role === "SYSTEM" || msg.message_type === "system";

        const div = document.createElement("div");
        div.className = "chat-msg" +
            (isMe ? " me" : "") +
            (isSystem ? " system" : "");
        if (msg.id) div.dataset.msgId = msg.id;

        if (isSystem) {
            const content = document.createElement("div");
            content.className = "msg-content";
            content.textContent = msg.content || "";
            div.appendChild(content);
        } else {
            const initials = (msg.sender_name || "?").substring(0, 2).toUpperCase();
            const avatar = document.createElement("div");
            avatar.className = "msg-avatar";
            avatar.textContent = initials;

            const content = document.createElement("div");
            content.className = "msg-content";

            const author = document.createElement("div");
            author.className = "msg-author";
            author.textContent = isMe ? "Vous" : (msg.sender_name || "Utilisateur");

            const text = document.createElement("div");
            text.className = "msg-text";
            text.textContent = msg.content || "";

            const time = document.createElement("div");
            time.className = "msg-time";
            time.textContent = formatTime(msg.created_at);

            content.appendChild(author);
            content.appendChild(text);
            content.appendChild(time);
            div.appendChild(avatar);
            div.appendChild(content);
        }

        msgList.appendChild(div);
        const nearBottom = msgList.scrollHeight - msgList.scrollTop - msgList.clientHeight < 100;
        if (nearBottom) msgList.scrollTop = msgList.scrollHeight;
    }

    function appendPdfMessage(msg) {
        const empty = msgList.querySelector(".chat-empty");
        if (empty) empty.remove();

        if (msg.id && msgList.querySelector(`[data-msg-id="${msg.id}"]`)) return;

        const isMe = parseInt(msg.sender_id, 10) === USER_ID;
        const div = document.createElement("div");
        div.className = "chat-msg" + (isMe ? " me" : "");
        if (msg.id) div.dataset.msgId = msg.id;

        const initials = (msg.sender_name || "?").substring(0, 2).toUpperCase();
        const avatar = document.createElement("div");
        avatar.className = "msg-avatar";
        avatar.textContent = initials;

        const content = document.createElement("div");
        content.className = "msg-content";

        const author = document.createElement("div");
        author.className = "msg-author";
        author.textContent = isMe ? "Vous" : (msg.sender_name || "Utilisateur");

        const pdfLink = document.createElement("a");
        pdfLink.href = `/api/contracts/messages/${msg.id}/download`;
        pdfLink.target = "_blank";
        pdfLink.style.cssText =
            "display:flex;align-items:center;gap:8px;padding:10px;" +
            "background:rgba(255,255,255,0.15);border-radius:8px;" +
            "color:inherit;text-decoration:none;font-weight:600;" +
            "font-size:12px;margin-bottom:4px;";
        pdfLink.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" stroke-width="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <path d="M14 2v6h6"/>
            </svg>
            <span>📄 ${escapeHtml(msg.filename || "document.pdf")}</span>
        `;

        const time = document.createElement("div");
        time.className = "msg-time";
        time.textContent = formatTime(msg.created_at);

        content.appendChild(author);
        content.appendChild(pdfLink);
        content.appendChild(time);

        div.appendChild(avatar);
        div.appendChild(content);
        msgList.appendChild(div);
        msgList.scrollTop = msgList.scrollHeight;
    }

    // =====================================================================
    //  Envoi message
    // =====================================================================
    if (inputForm) {
        inputForm.addEventListener("submit", (e) => {
            e.preventDefault();
            sendMessage();
        });
    }

    if (textarea) {
        textarea.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });

        let typingTimer = null;
        textarea.addEventListener("input", () => {
            if (!socket) return;
            socket.emit("typing", { contract_id: CONTRACT_ID, is_typing: true });
            clearTimeout(typingTimer);
            typingTimer = setTimeout(() => {
                socket.emit("typing", { contract_id: CONTRACT_ID, is_typing: false });
            }, 1500);
        });

        textarea.addEventListener("input", function () {
            this.style.height = "auto";
            this.style.height = Math.min(this.scrollHeight, 100) + "px";
        });
    }

    async function sendMessage() {
        const content = (textarea.value || "").trim();
        if (!content) return;
        if (CHAT_LOCKED) {
            await showAlert({
                title: "Chat verrouillé",
                message: "Ce contrat est signé. Le chat est en lecture seule.",
                variant: "danger",
            });
            return;
        }

        textarea.value = "";
        textarea.style.height = "auto";

        if (socket && socket.connected) {
            socket.emit("send_message", { contract_id: CONTRACT_ID, content });
        } else {
            try {
                const r = await fetch(`/api/contracts/${CONTRACT_ID}/messages`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "X-CSRFToken": getCsrf()
                    },
                    credentials: "same-origin",
                    body: JSON.stringify({ content }),
                });
                const data = await r.json();
                if (data.ok) {
                    appendMessage({
                        id: data.message_id,
                        sender_id: USER_ID,
                        sender_name: USER_NAME,
                        content: content,
                        created_at: data.created_at,
                        message_type: "text",
                    });
                }
            } catch (e) {}
        }

        if (socket) socket.emit("typing", { contract_id: CONTRACT_ID, is_typing: false });
    }

    // =====================================================================
    //  Typing indicator
    // =====================================================================
    let typingTimeout = null;
    function showTyping(data) {
        if (!typingEl) return;
        if (data.is_typing) {
            typingEl.innerHTML = `${escapeHtml(data.user_name)} est en train d'écrire<span class="dot"></span><span class="dot"></span><span class="dot"></span>`;
            clearTimeout(typingTimeout);
            typingTimeout = setTimeout(() => { typingEl.innerHTML = ""; }, 2000);
        } else {
            typingEl.innerHTML = "";
        }
    }

    // =====================================================================
    //  Mark read
    // =====================================================================
    async function markAllRead() {
        try {
            await fetch(`/api/contracts/${CONTRACT_ID}/messages/read`, {
                method: "POST",
                headers: { "X-CSRFToken": getCsrf() },
                credentials: "same-origin",
            });
            if (badge) badge.style.display = "none";
        } catch (e) {}
    }

    // =====================================================================
    //  Utilitaires
    // =====================================================================
    function formatTime(iso) {
        if (!iso) return "";
        try {
            return new Date(iso).toLocaleTimeString("fr-FR",
                { hour: "2-digit", minute: "2-digit" });
        } catch (e) { return ""; }
    }

    function escapeHtml(s) {
        return String(s || "").replace(/[&<>"']/g, c => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;",
            '"': "&quot;", "'": "&#39;"
        }[c]));
    }

    function getCsrf() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        if (meta) return meta.content;
        const input = document.querySelector('input[name="csrf_token"]');
        if (input) return input.value;
        return "";
    }

    // =====================================================================
    //  Upload PDF
    // =====================================================================
    if (attachBtn && pdfInput) {
        attachBtn.addEventListener("click", () => pdfInput.click());

        pdfInput.addEventListener("change", async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            if (!file.name.toLowerCase().endsWith(".pdf")) {
                await showAlert({
                    title: "Format invalide",
                    message: "Seuls les fichiers PDF sont acceptés.",
                    variant: "danger",
                });
                pdfInput.value = "";
                return;
            }
            if (file.size > 10 * 1024 * 1024) {
                await showAlert({
                    title: "Fichier trop gros",
                    message: "Le fichier ne doit pas dépasser 10 Mo.",
                    variant: "danger",
                });
                pdfInput.value = "";
                return;
            }

            const formData = new FormData();
            formData.append("document", file);

            attachBtn.disabled = true;
            attachBtn.style.opacity = "0.5";

            try {
                const r = await fetch(
                    `/api/contracts/${CONTRACT_ID}/messages/upload-pdf`,
                    {
                        method: "POST",
                        headers: { "X-CSRFToken": getCsrf() },
                        credentials: "same-origin",
                        body: formData,
                    }
                );
                const data = await r.json();
                pdfInput.value = "";

                if (!data.ok) {
                    await showAlert({
                        title: "Erreur d'upload",
                        message: data.error || "Erreur lors de l'upload.",
                        variant: "danger",
                    });
                    return;
                }

                appendPdfMessage({
                    id:          data.message_id,
                    sender_id:   data.sender_id,
                    sender_name: data.sender_name,
                    filename:    data.filename,
                    created_at:  data.created_at,
                });

                if (socket && socket.connected) {
                    socket.emit("pdf_sent", { contract_id: CONTRACT_ID });
                }

            } catch (err) {
                console.error("[chat] upload error", err);
                await showAlert({
                    title: "Erreur réseau",
                    message: "Impossible de contacter le serveur.",
                    variant: "danger",
                });
            } finally {
                attachBtn.disabled = false;
                attachBtn.style.opacity = "1";
            }
        });
    }

    // =====================================================================
    //  Bouton "Demander une modification"
    // =====================================================================
    if (btnRequest) {
        btnRequest.addEventListener("click", async () => {
            const ok = await showConfirm({
                title: "Demander une modification",
                message: "Créer une demande de modification pour ce contrat signé ? " +
                         "Le chat sera déverrouillé pour négocier.",
                confirmLabel: "Demander",
                cancelLabel: "Annuler",
                variant: "primary",
            });
            if (!ok) return;

            btnRequest.disabled = true;
            btnRequest.textContent = "⏳ Création…";

            try {
                const r = await fetch(
                    `/api/contracts/${CONTRACT_ID}/amendments/request`,
                    {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "Accept": "application/json",
                            "X-CSRFToken": getCsrf(),
                        },
                        credentials: "same-origin",
                    }
                );
                const data = await r.json();

                if (!data.ok) {
                    await showAlert({
                        title: "Erreur",
                        message: data.error || "Impossible de créer la demande.",
                        variant: "danger",
                    });
                    btnRequest.disabled = false;
                    btnRequest.textContent = "📝 Demander une modification";
                    return;
                }

                await showAlert({
                    title: "Demande créée",
                    message: "Votre demande de modification a été enregistrée.\n\n" +
                             "Le chat est maintenant ouvert pour négocier. " +
                             "Une fois d'accord, l'un de vous peut cliquer sur " +
                             "'Finaliser la modification'.",
                    variant: "success",
                });
                window.location.reload();

            } catch (e) {
                await showAlert({
                    title: "Erreur réseau",
                    message: "Impossible de contacter le serveur.",
                    variant: "danger",
                });
                btnRequest.disabled = false;
                btnRequest.textContent = "📝 Demander une modification";
            }
        });
    }

    // =====================================================================
    //  Bouton "Finaliser"
    // =====================================================================
    if (btnFinalize) {
        btnFinalize.addEventListener("click", async () => {
            const ok = await showConfirm({
                title: "Finaliser la modification",
                message: "Analyser la conversation et créer un avenant ?",
                confirmLabel: "Finaliser",
                cancelLabel: "Annuler",
                variant: "primary",
            });
            if (!ok) return;

            btnFinalize.disabled = true;
            btnFinalize.textContent = "⚡ Analyse IA en cours…";

            if (iaResult) {
                iaResult.style.display = "block";
                iaResult.innerHTML = `
                    <div style="font-size:13px;color:#4338ca;padding:8px;
                                text-align:center;">
                        ⚡ L'IA analyse la conversation…
                    </div>
                `;
            }

            try {
                const r = await fetch(
                    `/api/contracts/${CONTRACT_ID}/amendments/finalize`,
                    {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "Accept": "application/json",
                            "X-CSRFToken": getCsrf(),
                        },
                        credentials: "same-origin",
                    }
                );
                const data = await r.json();

                if (!data.ok) {
                    if (iaResult) {
                        iaResult.innerHTML = `
                            <div style="color:#dc2626;font-size:13px;
                                        padding:8px;line-height:1.5;">
                                ❌ ${escapeHtml(data.error || "Erreur inconnue.")}
                            </div>
                        `;
                    }
                    btnFinalize.disabled = false;
                    btnFinalize.textContent = "✅ Finaliser";
                    return;
                }

                renderSuccess(data);

            } catch (e) {
                console.error("[chat] finalize error", e);
                if (iaResult) {
                    iaResult.innerHTML = `
                        <div style="color:#dc2626;font-size:13px;
                                    padding:8px;">
                            ❌ Erreur réseau.
                        </div>
                    `;
                }
                btnFinalize.disabled = false;
                btnFinalize.textContent = "✅ Finaliser";
            }
        });
    }

    function renderSuccess(data) {
        const mode = data.mode || "direct";
        const isAmendment = mode === "amendment";

        let html = `
            <div style="font-size:14px;color:#059669;font-weight:700;
                        margin-bottom:10px;text-align:center;">
                ✅ ${isAmendment ? "Avenant créé" : "Contrat modifié"} avec succès !
            </div>
        `;

        if (data.pdf_replaced) {
            html += `
                <div style="padding:10px;background:#ecfdf5;
                            border-left:3px solid #10b981;border-radius:6px;
                            font-size:12px;color:#047857;margin-bottom:10px;">
                    📎 PDF remplacé : <strong>${escapeHtml(data.pdf_filename || "")}</strong>
                </div>
            `;
        }

        html += `
            <div style="font-size:12px;color:#64748b;margin-bottom:8px;">
                <strong>Provider :</strong> ${escapeHtml(data.provider || "—")}
            </div>
            <div style="font-size:12px;color:#0f172a;margin-bottom:10px;
                        line-height:1.5;">
                <strong>📄 Résumé :</strong><br>
                ${escapeHtml(data.resume || "—")}
            </div>
        `;

        let modifs = [];
        if (isAmendment) {
            modifs = (data.applied_modifications || []).map(m => ({
                champ: m.champ, valeur: m.nouvelle_valeur,
            }));
        } else {
            modifs = (data.applied_fields || []).map(f => ({
                champ: f, valeur: "mis à jour",
            }));
        }

        if (modifs.length > 0) {
            html += `
                <div style="font-size:12px;color:#4338ca;font-weight:600;
                            margin-bottom:6px;">
                    ✨ ${modifs.length} modification(s) appliquée(s) :
                </div>
            `;
            modifs.forEach(m => {
                html += `
                    <div style="padding:8px;background:#fff;border-radius:6px;
                                border-left:3px solid #0d9488;font-size:12px;
                                margin-bottom:6px;">
                        <div style="font-weight:700;color:#0f766e;
                                    text-transform:uppercase;font-size:11px;
                                    margin-bottom:4px;">
                            ${escapeHtml(m.champ || "—")}
                        </div>
                        <div style="color:#0f172a;">
                            → ${escapeHtml(m.valeur || "—")}
                        </div>
                    </div>
                `;
            });
        }

        const redirectUrl = isAmendment
            ? `/employee/contracts/${data.amendment_contract_id}`
            : `/employee/contracts/${data.contract_id}`;

        html += `
            <div style="display:flex;gap:8px;margin-top:12px;">
                <a href="${redirectUrl}"
                   style="flex:1;padding:10px;background:#0d9488;color:#fff;
                          border:none;border-radius:6px;cursor:pointer;
                          font-weight:600;font-size:13px;text-align:center;
                          text-decoration:none;display:block;">
                    ${isAmendment ? "Voir l'avenant →" : "Voir le contrat →"}
                </a>
            </div>
        `;

        if (iaResult) {
            iaResult.innerHTML = html;
        }

        setTimeout(() => {
            window.location.href = redirectUrl;
        }, 3000);
    }

    // =====================================================================
    //  Badge non-lus
    // =====================================================================
    (async function refreshUnreadBadge() {
        try {
            const r = await fetch(`/api/contracts/${CONTRACT_ID}/messages/count`, {
                headers: { "Accept": "application/json" },
                credentials: "same-origin",
            });
            const data = await r.json();
            if (data.count > 0 && badge) {
                badge.textContent = data.count > 99 ? "99+" : data.count;
                badge.style.display = "flex";
            }
        } catch (e) {}
    })();

    // =====================================================================
    //  Bandeau "Avenant" — auto-share
    // =====================================================================
    const amendmentBanner = document.getElementById("amendment-banner");
    const amendmentShareList = document.getElementById("amendment-share-list");
    const btnAutoShare = document.getElementById("btn-auto-share");
    const btnDismissBanner = document.getElementById("btn-dismiss-banner");

    if (amendmentBanner) {
        (async function checkAmendment() {
            try {
                const r = await fetch(
                    `/api/contracts/${CONTRACT_ID}/amendments/share-preview`,
                    {
                        headers: { "Accept": "application/json" },
                        credentials: "same-origin",
                    }
                );
                const data = await r.json();

                if (!data.ok || !data.is_amendment || !data.has_any) {
                    return;
                }

                const notShared = data.users.filter(u => !u.already_shared);

                if (notShared.length === 0) {
                    return;
                }

                amendmentBanner.style.display = "block";

                amendmentShareList.innerHTML = notShared.map(u => `
                    <div style="display:flex; justify-content:space-between;
                                align-items:center; padding:4px 0;
                                border-bottom:1px solid #f1f5f9;">
                        <div>
                            <strong style="color:#0f172a;">${escapeHtml(u.username)}</strong>
                            <span style="color:#64748b; margin-left:6px;">
                                (${escapeHtml(u.email)})
                            </span>
                        </div>
                        <div style="display:flex; gap:4px;">
                            ${u.permissions.map(p => `
                                <span style="background:#e0f2f1; color:#0f766e;
                                             padding:2px 6px; border-radius:4px;
                                             font-size:11px;">${escapeHtml(p)}</span>
                            `).join("")}
                        </div>
                    </div>
                `).join("");

                if (btnAutoShare) {
                    btnAutoShare.addEventListener("click", async () => {
                        const ok = await showConfirm({
                            title: "Partager automatiquement",
                            message: `Copier les permissions de ${notShared.length} ` +
                                     `utilisateur(s) depuis le contrat original ?`,
                            confirmLabel: "Partager",
                            cancelLabel: "Annuler",
                            variant: "primary",
                        });
                        if (!ok) return;

                        btnAutoShare.disabled = true;
                        btnAutoShare.textContent = "⏳ Partage…";

                        try {
                            const r = await fetch(
                                `/api/contracts/${CONTRACT_ID}/amendments/auto-share`,
                                {
                                    method: "POST",
                                    headers: {
                                        "Content-Type": "application/json",
                                        "Accept": "application/json",
                                        "X-CSRFToken": getCsrf(),
                                    },
                                    credentials: "same-origin",
                                }
                            );
                            const res = await r.json();

                            if (!res.ok) {
                                await showAlert({
                                    title: "Erreur",
                                    message: res.error || "Erreur lors du partage.",
                                    variant: "danger",
                                });
                                btnAutoShare.disabled = false;
                                btnAutoShare.textContent = "✅ Partager automatiquement";
                                return;
                            }

                            await showAlert({
                                title: "Partage effectué",
                                message: `${res.shared_count} utilisateur(s) ont reçu les permissions.`,
                                variant: "success",
                            });
                            window.location.reload();

                        } catch (e) {
                            await showAlert({
                                title: "Erreur réseau",
                                message: "Impossible de contacter le serveur.",
                                variant: "danger",
                            });
                            btnAutoShare.disabled = false;
                            btnAutoShare.textContent = "✅ Partager automatiquement";
                        }
                    });
                }

                if (btnDismissBanner) {
                    btnDismissBanner.addEventListener("click", () => {
                        amendmentBanner.style.display = "none";
                    });
                }

            } catch (e) {
                console.error("[chat] share-preview error", e);
            }
        })();
    }
})();