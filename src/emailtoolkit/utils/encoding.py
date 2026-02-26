# ./src/emailtoolkit/utils/encoding.py
# emailtoolkit/utils/encoding.py

from __future__ import annotations
import re


def decode_cf_email(encoded_string: str) -> str:
    """Decodes a Cloudflare-protected email address."""
    try:
        r = int(encoded_string[:2], 16)
        email = "".join(
            [
                chr(int(encoded_string[i : i + 2], 16) ^ r)
                for i in range(2, len(encoded_string), 2)
            ]
        )
        return email
    except (ValueError, IndexError):
        return ""


def find_and_decode_cf_emails(html_text: str) -> list[str]:
    """Finds all Cloudflare-protected emails in a block of HTML and decodes them."""
    if not html_text:
        return []

    # Regex to find the data-cfemail attribute in an <a> tag
    # e.g., <a href="/cdn-cgi/l/email-protection" class="__cf_email__" data-cfemail="xxxxxxxx">...</a>
    cf_protected = re.findall(r'data-cfemail="([a-zA-Z0-9]+)"', html_text)

    decoded_emails = [decode_cf_email(encoded) for encoded in cf_protected]

    # Return only non-empty, successfully decoded emails
    return [email for email in decoded_emails if email]
