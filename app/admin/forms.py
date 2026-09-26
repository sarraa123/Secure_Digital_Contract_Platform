from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo


class ManagerCreationForm(FlaskForm):

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

    temporary_password = PasswordField(
        "Mot de passe temporaire",
        validators=[
            DataRequired(),
            Length(min=12, max=128),
        ],
    )

    confirm_password = PasswordField(
        "Confirmer le mot de passe temporaire",
        validators=[
            DataRequired(),
            EqualTo(
                "temporary_password",
                message="Les mots de passe doivent être identiques.",
            ),
        ],
    )

    submit = SubmitField("Créer le gestionnaire")