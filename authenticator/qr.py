import io
import base64
import qrcode


def generate_qr_code(provisioning_uri):
    """Generate a Base64 PNG QR code from a TOTP provisioning URI."""

    if not isinstance(provisioning_uri, str) or not provisioning_uri.strip():
        raise ValueError("Provisioning URI is required.")

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
    )

    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    image = qr.make_image(
        fill_color="black",
        back_color="white",
    )

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")

    return base64.b64encode(
        buffer.getvalue()
    ).decode("ascii")


def generate_qr_matrix(provisioning_uri):
    """Return the QR modules as rows of 1/0 strings for browser-safe drawing."""
    if not isinstance(provisioning_uri, str) or not provisioning_uri.strip():
        raise ValueError("Provisioning URI is required.")

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=1,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    return [
        "".join("1" if module else "0" for module in row)
        for row in qr.get_matrix()
    ]
