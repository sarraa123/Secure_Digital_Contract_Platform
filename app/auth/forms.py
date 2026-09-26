from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import (
    DataRequired,
    Email,
    Length,
    EqualTo,
)
from wtforms import BooleanField

class RegistrationForm(FlaskForm):
    username = StringField(
        "Nom d'utilisateur",
        validators=[
            DataRequired(),
            Length(min=3, max=80),
        ],
    )

    email = StringField(
        "Email",
        validators=[
            DataRequired(),
            Email(),
            Length(max=255),
        ],
    )

    password = PasswordField(
        "Mot de passe",
        validators=[
            DataRequired(),
            Length(min=12, max=128),
        ],
    )

    confirm_password = PasswordField(
        "Confirmer le mot de passe",
        validators=[
            DataRequired(),
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