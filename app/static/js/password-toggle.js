// Affiche/masque le contenu des champs mot de passe (bouton "œil").
document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-toggle-password]").forEach(function (button) {
        button.addEventListener("click", function () {
            var wrapper = button.closest(".password-field");
            if (!wrapper) {
                return;
            }

            var input = wrapper.querySelector("input");
            if (!input) {
                return;
            }

            var isHidden = input.getAttribute("type") === "password";

            input.setAttribute("type", isHidden ? "text" : "password");
            button.classList.toggle("is-visible", isHidden);
            button.setAttribute(
                "aria-label",
                isHidden ? "Masquer le mot de passe" : "Afficher le mot de passe"
            );
        });
    });
});