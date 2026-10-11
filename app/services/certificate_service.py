"""
Génération des certificats de signature :
  1. PDF de preuve (lisible humainement)
  2. Certificat cryptographique .txt (vérifiable avec openssl)
"""
import hashlib
import io
from datetime import timezone

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image as RLImage, HRFlowable,
)

from app.services.signature_image_service import decrypt_image, sha256_hex


def _public_key_fingerprint(pem_public: str) -> str:
    from cryptography.hazmat.primitives import serialization
    pk = serialization.load_pem_public_key(pem_public.encode("utf-8"))
    der = pk.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _format_dt_utc(dt) -> str:
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_hash(h: str, chunk: int = 8) -> str:
    if not h:
        return "—"
    return " ".join(h[i:i + chunk] for i in range(0, len(h), chunk))


# =========================================================================
#  PDF
# =========================================================================
def build_certificate_pdf(*, contract_view, signature, signer,
                          signer_ip=None, verify_url=None) -> bytes:
    buf = io.BytesIO()

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title=f"Certificat de signature — {contract_view.title}",
        author="Veridoc",
        subject="Certificat de signature électronique",
    )

    styles = getSampleStyleSheet()
    st_title = ParagraphStyle("CertTitle", parent=styles["Heading1"],
                              fontSize=18, leading=22, alignment=TA_CENTER,
                              textColor=colors.HexColor("#0f172a"))
    st_sub = ParagraphStyle("CertSub", parent=styles["Normal"],
                            fontSize=10, leading=13, alignment=TA_CENTER,
                            textColor=colors.HexColor("#475569"))
    st_h2 = ParagraphStyle("CertH2", parent=styles["Heading2"],
                           fontSize=12, leading=15, spaceBefore=6, spaceAfter=4,
                           textColor=colors.HexColor("#0f172a"))
    st_label = ParagraphStyle("CertLabel", parent=styles["Normal"],
                              fontSize=9, leading=12,
                              textColor=colors.HexColor("#64748b"))
    st_value = ParagraphStyle("CertValue", parent=styles["Normal"],
                              fontSize=10, leading=13,
                              textColor=colors.HexColor("#0f172a"))
    st_mono = ParagraphStyle("CertMono", parent=styles["Normal"],
                             fontName="Courier", fontSize=8, leading=11,
                             textColor=colors.HexColor("#0f172a"))

    story = []
    story.append(Paragraph("Certificat de signature électronique", st_title))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Document émis automatiquement par Veridoc — preuve de signature.",
        st_sub))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=0.6,
                            color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 12))

    # --- 1. Contrat
    story.append(Paragraph("1. Contrat", st_h2))
    story.append(_kv_table([
        ["Titre",        contract_view.title],
        ["Version",      str(contract_view.version)],
        ["Type",         contract_view.contract_type],
        ["Propriétaire", contract_view.owner_name],
        ["Statut",       contract_view.status],
        ["Hash document (SHA-256)",
         Paragraph(f"<font face='Courier' size='8'>"
                   f"{_fmt_hash(signature.document_hash)}</font>", st_value)],
    ]))
    story.append(Spacer(1, 10))

    # --- 2. Signataire
    story.append(Paragraph("2. Signataire", st_h2))
    story.append(_kv_table([
        ["Nom",   signer.username],
        ["Email", signer.email],
        ["Rôle",  signer.role],
        ["Date de signature", _format_dt_utc(signature.signed_at)],
        ["Adresse IP", signer_ip or "Non disponible"],
    ]))
    story.append(Spacer(1, 10))

    # --- 3. Signature manuscrite
    story.append(Paragraph("3. Signature manuscrite", st_h2))
    try:
        img_model = signature.signature_image
        png_bytes = decrypt_image(img_model.encrypted_image)
        integrity_ok = (sha256_hex(png_bytes) == img_model.image_hash)

        rl_img = RLImage(io.BytesIO(png_bytes),
                         width=150 * mm, height=60 * mm,
                         kind="proportional")
        story.append(rl_img)
        story.append(Spacer(1, 4))

        status_txt = ("<font color='#0d9488'>Intégrité vérifiée</font>"
                      if integrity_ok else
                      "<font color='#dc2626'>Intégrité compromise</font>")

        story.append(Paragraph(
            f"<font size='8'>Hash SHA-256 de l'image : "
            f"<font face='Courier'>{_fmt_hash(img_model.image_hash)}</font>"
            f"</font><br/>"
            f"<font size='8'>{status_txt}</font>", st_label))
    except Exception:
        story.append(Paragraph("Image de signature indisponible.", st_label))

    story.append(Spacer(1, 10))

    # --- 4. Crypto
    story.append(Paragraph("4. Preuve cryptographique", st_h2))
    try:
        pk_fp = _public_key_fingerprint(signer.public_key_pem)
    except Exception:
        pk_fp = "—"

    story.append(_kv_table([
        ["Algorithme", signature.algorithm],
        ["Clé publique (empreinte SHA-256)",
         Paragraph(f"<font face='Courier' size='8'>{_fmt_hash(pk_fp)}</font>",
                   st_value)],
    ]))

    if signer.x509_certificate_pem:
        try:
            from app.services.x509_service import fingerprint_sha256
            x509_fp = fingerprint_sha256(signer.x509_certificate_pem)
        except Exception:
            x509_fp = "—"
        story.append(Spacer(1, 4))
        story.append(_kv_table([
            ["Certificat X.509 (empreinte SHA-256)",
             Paragraph(f"<font face='Courier' size='8'>{_fmt_hash(x509_fp)}</font>",
                       st_value)],
        ]))

    sig_b64 = signature.signature
    sig_short = (sig_b64 if len(sig_b64) <= 120
                 else sig_b64[:120] + " … (tronqué)")
    story.append(Spacer(1, 4))
    story.append(Paragraph("Signature RSA-PSS (Base64) :", st_label))
    story.append(Paragraph(sig_short, st_mono))

    if verify_url:
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=0.4,
                                color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f"<font size='8'>Vérification en ligne : "
            f"<font face='Courier'>{verify_url}</font></font>", st_label))

    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<font size='7' color='#64748b'>Ce certificat atteste qu'un document "
        "a été signé électroniquement via Veridoc. Il peut être vérifié "
        "indépendamment en recalculant le SHA-256 du contenu signé et en "
        "vérifiant la signature RSA-PSS avec la clé publique du signataire."
        "</font>", st_sub))

    doc.build(story)
    return buf.getvalue()


def _kv_table(rows):
    data = [[Paragraph(k, ParagraphStyle(
                "k", fontName="Helvetica-Bold", fontSize=9,
                textColor=colors.HexColor("#475569"))),
             v if not isinstance(v, Paragraph) else v]
            for k, v in rows]
    t = Table(data, colWidths=[55 * mm, 120 * mm], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#f1f5f9")),
    ]))
    return t


# =========================================================================
#  Certificat crypto .txt
# =========================================================================
def build_certificate_crypto(*, contract_view, signature, signer,
                             signer_ip=None) -> str:
    try:
        image_hash = signature.signature_image.image_hash
    except Exception:
        image_hash = "—"

    try:
        pk_fp = _public_key_fingerprint(signer.public_key_pem)
    except Exception:
        pk_fp = "—"

    x509_fp = "—"
    if signer.x509_certificate_pem:
        try:
            from app.services.x509_service import fingerprint_sha256
            x509_fp = fingerprint_sha256(signer.x509_certificate_pem)
        except Exception:
            pass

    lines = []
    add = lines.append

    add("-----BEGIN VERIDOC SIGNATURE CERTIFICATE-----")
    add("Version: 1")
    add(f"Issued-At: {_format_dt_utc(signature.signed_at)}")
    add(f"Contract-ID: {contract_view.id}")
    add(f"Contract-Title: {contract_view.title}")
    add(f"Contract-Version: {contract_view.version}")
    add(f"Owner: {contract_view.owner_name}")
    add("")
    add("-----BEGIN SIGNER-----")
    add(f"Name: {signer.username}")
    add(f"Email: {signer.email}")
    add(f"Role: {signer.role}")
    add(f"IP-Address: {signer_ip or 'Non disponible'}")
    add("-----END SIGNER-----")
    add("")
    add("-----BEGIN DOCUMENT HASHES-----")
    add(f"Signed-Content-SHA256: {signature.document_hash}")
    add(f"Signature-Image-SHA256: {image_hash}")
    add("-----END DOCUMENT HASHES-----")
    add("")
    add("-----BEGIN SIGNATURE-----")
    add(f"Algorithm: {signature.algorithm}")
    add(f"Public-Key-Fingerprint-SHA256: {pk_fp}")
    add(f"X509-Certificate-Fingerprint-SHA256: {x509_fp}")
    add("Signature-Base64:")
    sig_b64 = signature.signature
    for i in range(0, len(sig_b64), 76):
        add(sig_b64[i:i + 76])
    add("-----END SIGNATURE-----")
    add("")
    add("-----BEGIN SIGNER PUBLIC KEY-----")
    add(signer.public_key_pem.strip())
    add("-----END SIGNER PUBLIC KEY-----")
    add("")
    if signer.x509_certificate_pem:
        add("-----BEGIN SIGNER X509 CERTIFICATE-----")
        add(signer.x509_certificate_pem.strip())
        add("-----END SIGNER X509 CERTIFICATE-----")
        add("")
    add("-----END VERIDOC SIGNATURE CERTIFICATE-----")

    return "\n".join(lines)