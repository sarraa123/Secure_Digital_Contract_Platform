from flask_wtf import FlaskForm
from wtforms import (
    StringField, SelectField, DateTimeLocalField, SubmitField,
)
from wtforms.validators import Optional, Length


class EventFilterForm(FlaskForm):
    class Meta:
        csrf = False  # GET form

    event_type = StringField("Type d'événement", validators=[Optional(), Length(max=100)])
    user_id = StringField("ID utilisateur", validators=[Optional(), Length(max=20)])
    ip_address = StringField("Adresse IP", validators=[Optional(), Length(max=45)])
    status = SelectField(
        "Statut",
        choices=[
            ("", "Tous"),
            ("SUCCESS", "Succès"),
            ("FAILURE", "Échec"),
            ("DENIED", "Refusé"),
            ("INFO", "Info"),
            ("CRITICAL", "Critique"),
        ],
        validators=[Optional()],
    )
    date_from = DateTimeLocalField("Du", format="%Y-%m-%dT%H:%M", validators=[Optional()])
    date_to = DateTimeLocalField("Au", format="%Y-%m-%dT%H:%M", validators=[Optional()])
    submit = SubmitField("Filtrer")


class AlertFilterForm(FlaskForm):
    class Meta:
        csrf = False

    severity = SelectField(
        "Sévérité",
        choices=[
            ("", "Toutes"),
            ("LOW", "Basse"),
            ("MEDIUM", "Moyenne"),
            ("HIGH", "Haute"),
            ("CRITICAL", "Critique"),
        ],
        validators=[Optional()],
    )
    status = SelectField(
        "Statut",
        choices=[
            ("", "Tous"),
            ("NEW", "Nouvelle"),
            ("TRIAGED", "Traitée"),
            ("INVESTIGATING", "En investigation"),
            ("RESOLVED", "Résolue"),
            ("FALSE_POSITIVE", "Faux positif"),
        ],
        validators=[Optional()],
    )
    submit = SubmitField("Filtrer")