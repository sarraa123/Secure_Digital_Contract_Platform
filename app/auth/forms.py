from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import (
    DataRequired,
    Email,
    Length,
    EqualTo,
    ValidationError,
)
from wtforms import BooleanField

import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import (
    DataRequired,
    Email,
    Length,
    EqualTo,
    ValidationError,
)


def validate_password_strength(form, field):
    """Valide la complexité du mot de passe : majuscule, minuscule, chiffre et caractère spécial."""
    password = field.data or ""

    if not re.search(r"[A-Z]", password):
        raise ValidationError(
            "Le mot de passe doit contenir au moins une lettre majuscule."
        )

    if not re.search(r"[a-z]", password):
        raise ValidationError(
            "Le mot de passe doit contenir au moins une lettre minuscule."
        )

    if not re.search(r"[0-9]", password):
        raise ValidationError(
            "Le mot de passe doit contenir au moins un chiffre."
        )

    if not re.search(r"[^A-Za-z0-9\s]", password):
        raise ValidationError(
            "Le mot de passe doit contenir au moins un caractère spécial."
        )

def validate_username_format(form, field):
    username = field.data or ""

    if not re.fullmatch(
        r"[A-Za-z0-9_-]+",
        username
    ):
        raise ValidationError(
            "Le nom d'utilisateur ne peut contenir "
            "que des lettres, chiffres, '_' et '-'."
        )
    
class RegistrationForm(FlaskForm):

    username = StringField(
        "Nom d'utilisateur",
        validators=[
            DataRequired(
                message="Le nom d'utilisateur est obligatoire."
            ),
            Length(
                min=3,
                max=80,
                message=(
                    "Le nom d'utilisateur doit contenir "
                    "entre 3 et 80 caractères."
                ),
            ),
            validate_username_format,
        ],
    )

    email = StringField(
        "Email",
        validators=[
            DataRequired(
                message="L'adresse email est obligatoire."
            ),
            Email(
                message="Veuillez saisir une adresse email valide."
            ),
            Length(
                max=255,
                message=(
                    "L'adresse email ne peut pas dépasser "
                    "255 caractères."
                ),
            ),
        ],
    )

    password = PasswordField(
        "Mot de passe",
        validators=[
            DataRequired(
                message="Le mot de passe est obligatoire."
            ),
            Length(
                min=12,
                max=128,
                message=(
                    "Le mot de passe doit contenir "
                    "entre 12 et 128 caractères."
                ),
            ),
            validate_password_strength,
        ],
    )

    confirm_password = PasswordField(
        "Confirmer le mot de passe",
        validators=[
            DataRequired(
                message="La confirmation du mot de passe est obligatoire."
            ),
            EqualTo(
                "password",
                message="Les mots de passe doivent être identiques.",
            ),
        ],
    )

    submit = SubmitField("Créer mon compte")


class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[
            DataRequired(message="L'adresse email est obligatoire."),
            Email(message="Veuillez saisir une adresse email valide."),
            Length(max=255),
        ],
    )

    password = PasswordField(
        "Mot de passe",
        validators=[
            DataRequired(message="Le mot de passe est obligatoire."),
            Length(max=128,message="Mot de passe invalide."),
        ],
    )

    submit = SubmitField("Se connecter")


class ChangePasswordForm(FlaskForm):

    current_password = PasswordField(
        "Mot de passe actuel",
        validators=[
            DataRequired(message="Le mot de passe actuel est obligatoire."),
            Length(max=128),
        ],
    )

    new_password = PasswordField(
        "Nouveau mot de passe",
        validators=[
            DataRequired(message="Le nouveau mot de passe est obligatoire."),
            Length(
                min=12,
                max=128,
                message=(
                    "Le mot de passe doit contenir "
                    "entre 12 et 128 caractères."
                ),
            ),
            validate_password_strength,
        ],
    )

    confirm_password = PasswordField(
        "Confirmer le nouveau mot de passe",
        validators=[
            DataRequired(
                message="La confirmation du mot de passe est obligatoire."
            ),
            EqualTo(
                "new_password",
                message="Les mots de passe doivent être identiques.",
            ),
        ],
    )

    submit = SubmitField("Modifier le mot de passe")

    submit = SubmitField("Créer mon compte")

class LoginForm(FlaskForm):
    email = StringField(
        "Email",
        validators=[
            DataRequired(),
            Email(),
            Length(max=255)
        ]
    )

    password = PasswordField(
        "Mot de passe",
        validators=[
            DataRequired(),
            Length(max=128)
        ]
    )

    submit = SubmitField("Se connecter")


class ChangePasswordForm(FlaskForm):

    current_password = PasswordField(
        "Mot de passe actuel",
        validators=[
            DataRequired(),
            Length(max=128),
        ],
    )

    new_password = PasswordField(
        "Nouveau mot de passe",
        validators=[
            DataRequired(),
            Length(min=12, max=128),
        ],
    )

    confirm_password = PasswordField(
        "Confirmer le nouveau mot de passe",
        validators=[
            DataRequired(),
            EqualTo(
                "new_password",
                message="Les mots de passe doivent être identiques.",
            ),
        ],
    )

    submit = SubmitField("Modifier le mot de passe")


def validate_password_strength(form, field):
    password = field.data or ""

    if not re.search(r"[A-Z]", password):
        raise ValidationError(
            "Le mot de passe doit contenir au moins "
            "une lettre majuscule."
        )

    if not re.search(r"[a-z]", password):
        raise ValidationError(
            "Le mot de passe doit contenir au moins "
            "une lettre minuscule."
        )

    if not re.search(r"[0-9]", password):
        raise ValidationError(
            "Le mot de passe doit contenir au moins "
            "un chiffre."
        )

    if not re.search(r"[^A-Za-z0-9\s]", password):
        raise ValidationError(
            "Le mot de passe doit contenir au moins "
            "un caractère spécial."
        )