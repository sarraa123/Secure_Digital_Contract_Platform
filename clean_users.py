"""
Script pour supprimer tous les utilisateurs et leurs données associées.
ATTENTION : opération destructive et irréversible après commit.
"""

from app import create_app
from app.models import (
    User,
    SecurityEvent,
    AuditLog,
    MFARecoveryCode,
    Signature,
    Notification,
)
from app.extensions import db


def main():
    app = create_app()

    with app.app_context():
        try:
            users = User.query.all()

            if not users:
                print("Aucun utilisateur à supprimer.")
                return

            print(f"⚠️ {len(users)} utilisateurs vont être supprimés.")

            # Afficher les comptes concernés avant suppression
            for user in users:
                print(f"   - {user.username} (id={user.id}, rôle={user.role})")

            confirmation = input(
                "\nConfirmer la suppression de TOUS les utilisateurs ? "
                "(oui/non) : "
            ).strip().lower()

            if confirmation != "oui":
                print("❌ Suppression annulée.")
                return

            for user in users:
                user_id = user.id
                username = user.username

                print(f"\n🗑️ Suppression de {username} (id={user_id})")

                # 1. Supprimer les notifications
                n_notifications = Notification.query.filter_by(
                    user_id=user_id
                ).delete(synchronize_session=False)

                # 2. Supprimer les événements de sécurité
                n_security = SecurityEvent.query.filter_by(
                    user_id=user_id
                ).delete(synchronize_session=False)

                # 3. Supprimer les journaux d'audit
                n_audit = AuditLog.query.filter_by(
                    user_id=user_id
                ).delete(synchronize_session=False)

                # 4. Supprimer les codes de récupération MFA
                n_mfa = MFARecoveryCode.query.filter_by(
                    user_id=user_id
                ).delete(synchronize_session=False)

                # 5. Supprimer les signatures créées par l'utilisateur
                n_signatures = Signature.query.filter_by(
                    signer_id=user_id
                ).delete(synchronize_session=False)

                print(f"   - {n_notifications} notifications supprimées")
                print(f"   - {n_security} événements de sécurité supprimés")
                print(f"   - {n_audit} journaux d'audit supprimés")
                print(f"   - {n_mfa} codes MFA supprimés")
                print(f"   - {n_signatures} signatures supprimées")

                # 6. Supprimer l'utilisateur
                db.session.delete(user)

                print(f"   ✅ {username} traité")

            # Valider toutes les suppressions en une seule transaction
            db.session.commit()

            print("\n🎉 Suppression terminée avec succès !")

        except Exception as e:
            db.session.rollback()
            print("\n❌ Erreur lors de la suppression :")
            print(e)
            print("↩️ Toutes les modifications de cette transaction ont été annulées.")

        finally:
            remaining = User.query.all()

            print(f"\n👥 Utilisateurs restants : {len(remaining)}")

            for user in remaining:
                print(
                    f"   - {user.username} "
                    f"({user.role}) | status={user.status}"
                )


if __name__ == "__main__":
    main()
