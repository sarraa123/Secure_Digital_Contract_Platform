"""
Script pour supprimer proprement 3 utilisateurs.
"""

from app import create_app
from app.models import (
    User,
    SecurityEvent,
    AuditLog,
    MFARecoveryCode,
    Signature,
)
from app.extensions import db


USERNAMES_TO_DELETE = ["Maram", "Firas", "mariam"]


def main():
    app = create_app()

    with app.app_context():
        for username in USERNAMES_TO_DELETE:
            u = User.query.filter_by(username=username).first()

            if not u:
                print(f"⚠️  {username} introuvable")
                continue

            print(f"\n🗑️  Suppression de {u.username} (id={u.id})")

            # 1. Supprime les security_events
            n1 = SecurityEvent.query.filter_by(user_id=u.id).delete()
            print(f"   - {n1} security_events supprimés")

            # 2. Supprime les audit_logs
            n2 = AuditLog.query.filter_by(user_id=u.id).delete()
            print(f"   - {n2} audit_logs supprimés")

            # 3. Supprime les codes MFA
            n3 = MFARecoveryCode.query.filter_by(user_id=u.id).delete()
            print(f"   - {n3} mfa_recovery_codes supprimés")

            # 4. Supprime les signatures
            n4 = Signature.query.filter_by(signer_id=u.id).delete()
            print(f"   - {n4} signatures supprimées")

            # 5. Supprime le user
            db.session.delete(u)
            print(f"   ✅ {u.username} supprimé")

        # Commit final
        db.session.commit()
        print("\n🎉 Suppression terminée !")

        # Vérification
        remaining = User.query.all()
        print(f"\n👥 Utilisateurs restants : {len(remaining)}")
        for user in remaining:
            print(f"   - {user.username} ({user.role}) | status={user.status}")


if __name__ == "__main__":
    main()