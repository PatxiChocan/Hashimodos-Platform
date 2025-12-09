# bank_client.py
"""
Cliente para la API REST Credit Cards del reto.

Usa:
  - GET /enablecardX/user1/DEBIT
  - GET /enablecardX/user1/CREDIT
  - GET /infocardsX/user1

Para /infocardsX:
  - Devuelve una cadena cifrada (JSON con un string).
  - Intentamos descifrarla con AES-256-ECB y la KeyString.
  - Si el descifrado no es un JSON válido, devolvemos el texto/hex
    sin romper la aplicación.

app.py importa:
  - bank_activate(card_number)
  - bank_deactivate(card_number)
  - bank_pay(card_number, amount, description)
  - bank_get_cards_info()
"""

import os
import base64
import json
from typing import Any, Dict, Optional

import requests

try:
    # pycryptodome
    from Crypto.Cipher import AES  # type: ignore
except ImportError:  # pragma: no cover
    AES = None


# --------------------------------------------------------------------
# CONFIG SEGÚN LA API
# --------------------------------------------------------------------
BASE_URL = os.getenv("CC_REST_URL", "http://10.11.0.25:4000")
TEAM_ID = os.getenv("CC_TEAM_ID", "4")
USERNAME = os.getenv("CC_USERNAME", "user1")

# KeyString que te han dado (puedes sacarla a un fichero/env si quieres)
KEYSTRING = os.getenv(
    "CC_KEYSTRING",
    "hzwkr8tRNVQY9hvwAY5T3cZJG8QbOjn2IJXVMW/boxf8yLDPsn3egW9ooSfZYbVMTrjuUZuFD5Ei9KTGvKdu5hRsd7qCYD4QNKowz7L29lwIWIWOB2a+uiTz2shNM1b/rX4ZQvcdJOdeVuWWxbw9Hq0kiNfCOivzXG9Hw5sTV7Rw2g8U25Mhms+jvMvqUxiWfmPMrnFIffKqcSyzDVa4Q5B8vlmAXIyyIpvNL75Nve2JLBoWGhaC3BXkEefCj7pZ",
)


class BankApiError(ValueError):
    """Errores de la API del banco (hereda de ValueError)."""


# --------------------------------------------------------------------
# FUNCIONES AUXILIARES
# --------------------------------------------------------------------

def _get_aes_key_from_keystring() -> Optional[bytes]:
    """
    Obtiene una clave AES-256 (32 bytes) a partir de KEYSTRING.

    No sabemos exactamente cómo la genera el servidor, así que:
      1) Intentamos decodificar base64 y usar los primeros 32 bytes.
      2) Si falla, usamos los primeros 32 caracteres como UTF-8.
    """
    # Intento 1: base64
    try:
        raw = base64.b64decode(KEYSTRING)
        if len(raw) >= 32:
            return raw[:32]
    except Exception:
        pass

    # Intento 2: directamente texto
    ks_bytes = KEYSTRING.encode("utf-8")
    if len(ks_bytes) >= 32:
        return ks_bytes[:32]

    # Si ni esto llega, no tenemos clave válida
    return None


def _pkcs7_unpad(data: bytes) -> bytes:
    """
    Quita padding PKCS#7 si tiene sentido. Si no, devuelve tal cual.
    """
    if not data:
        return data
    pad = data[-1]
    if pad < 1 or pad > 16:
        return data
    if len(data) < pad:
        return data
    if data[-pad:] != bytes([pad]) * pad:
        return data
    return data[:-pad]


def _decrypt_infocards(cipher_b64: str) -> Dict[str, Any]:
    """
    Intenta descifrar la cadena devuelta por /infocardsX.

    Devuelve SIEMPRE un dict:
      - Si todo va bien y es JSON válido: ese JSON.
      - Si no: {'raw_plaintext': ..., 'raw_ciphertext': ...}
    """
    if AES is None:
        # Sin Crypto no podemos descifrar, devolvemos el cifrado en claro
        return {"raw_ciphertext": cipher_b64, "error": "Crypto no disponible"}

    key = _get_aes_key_from_keystring()
    if not key:
        return {"raw_ciphertext": cipher_b64, "error": "KeyString no válida"}

    try:
        cipher_bytes = base64.b64decode(cipher_b64)
    except Exception as e:
        return {
            "raw_ciphertext": cipher_b64,
            "error": f"No es base64 válido: {e}",
        }

    try:
        cipher = AES.new(key, AES.MODE_ECB)
        plain = cipher.decrypt(cipher_bytes)
        plain = _pkcs7_unpad(plain)
        text = plain.decode("utf-8", errors="ignore").strip()
    except Exception as e:
        return {
            "raw_ciphertext": cipher_b64,
            "error": f"Error descifrando AES: {e}",
        }

    # Intentar parsear JSON
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
        # Si es otra cosa (lista, string...), lo envolvemos
        return {"data": data}
    except Exception:
        # Plaintext no es JSON válido → lo devolvemos como texto
        return {"raw_plaintext": text, "raw_ciphertext": cipher_b64}


# --------------------------------------------------------------------
# FUNCIONES PÚBLICAS QUE USA app.py
# --------------------------------------------------------------------
def bank_get_cards_info() -> Dict[str, Any]:
    """
    Llama a /infocardsX/user1 y devuelve info descifrada (si se puede).

    NUNCA levanta excepción salvo fallo HTTP o de red grave; en el peor
    caso devuelve un dict con campos 'error' + datos en bruto.
    """
    url = f"{BASE_URL}/infocards{TEAM_ID}/{USERNAME}"

    try:
        resp = requests.get(url, timeout=5)
    except requests.RequestException as e:
        raise BankApiError(f"Error de conexión con infocardsX: {e}")

    if resp.status_code != 200:
        raise BankApiError(
            f"infocardsX devolvió HTTP {resp.status_code} en {url}"
        )

    # Según el curl, es un JSON con un string:
    #
    #   "XRCc/oO4lbJtBvnN60ixRkdNXXWFr1co..."
    #
    try:
        encrypted_str = resp.json()
    except Exception:
        # Si por lo que sea no es JSON, usamos el texto tal cual
        encrypted_str = resp.text.strip().strip('"')

    if not isinstance(encrypted_str, str):
        # Por si algún día cambian el formato
        return {
            "raw_response": resp.text,
            "error": "Formato inesperado de infocardsX (no es string)",
        }

    # Intentar descifrar; SIEMPRE devolvemos un dict
    return _decrypt_infocards(encrypted_str)


def _enable_card_type(card_type: str) -> None:
    """
    Llama a:
      GET /enablecardX/user1/DEBIT  o  /CREDIT

    No intentamos leer JSON porque la API cifra la respuesta; solo
    comprobamos que responda 200 OK.
    """
    card_type = card_type.upper()
    if card_type not in ("DEBIT", "CREDIT"):
        raise BankApiError(f"Tipo de tarjeta no válido: {card_type}")

    url = f"{BASE_URL}/enablecard{TEAM_ID}/{USERNAME}/{card_type}"

    try:
        resp = requests.get(url, timeout=5)
    except requests.RequestException as e:
        raise BankApiError(f"Error de conexión con enablecardX: {e}")

    if resp.status_code != 200:
        raise BankApiError(
            f"enablecardX devolvió HTTP {resp.status_code} en {url}"
        )
    # No devolvemos nada; asumimos que el mock ha cambiado la tarjeta activa.


def bank_activate(card_number: str) -> None:
    """
    Activa una tarjeta en la API CreditCards.

    La API no recibe el número de tarjeta, solo el tipo (DEBIT/CREDIT),
    así que deducimos el tipo a partir del número que usamos en la BD.

    Por ejemplo:
      DEMO-DEBIT-0001  -> DEBIT
      DEMO-CREDIT-0001 -> CREDIT
    """
    num = (card_number or "").upper()

    if "DEBIT" in num:
        cardtype = "DEBIT"
    elif "CREDIT" in num:
        cardtype = "CREDIT"
    else:
        # Si no encontramos ninguna pista, por seguridad lanzamos error
        raise BankApiError(
            f"No se puede deducir el tipo (DEBIT/CREDIT) "
            f"del número de tarjeta: {card_number}"
        )

    _enable_card_type(cardtype)


def bank_deactivate(card_number: str) -> None:
    """
    No hay endpoint específico de 'desactivar' en la API CreditCards.
    En el mock, al habilitar DEBIT, la de crédito queda desactivada y viceversa,
    así que aquí no tenemos que hacer nada.
    """
    return


def bank_pay(card_number: str, amount: float, description: str | None = None) -> dict:
    """
    La API del documento NO define un endpoint de pago, solo gestión de
    tarjetas (infocards/enablecard).

    El pago real lo gestiona tu propia aplicación (tabla transactions en MySQL),
    así que aquí simplemente simulamos que el banco ha aprobado el pago y
    devolvemos un objeto parecido a la respuesta de un banco real.
    """
    fake_tx_id = f"LOCAL-{card_number}-{int(amount * 100)}"
    return {
        "status": "approved",
        "transaction_id": fake_tx_id,
        "error_code": None,
        "error_message": None,
    }

