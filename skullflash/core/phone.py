"""Phone number lookup using the phonenumbers library."""
from __future__ import annotations

from dataclasses import dataclass

import phonenumbers
from phonenumbers import carrier, geocoder
from loguru import logger


_TYPE_LABELS = {
    phonenumbers.PhoneNumberType.MOBILE: "Mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed / Mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
    phonenumbers.PhoneNumberType.VOIP: "VoIP",
    phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
}


@dataclass
class PhoneResult:
    number: str
    valid: bool
    location: str = ""
    carrier_name: str = ""
    number_type: str = ""
    country: str = ""
    national_format: str = ""
    international_format: str = ""


def lookup_phone(number: str) -> PhoneResult:
    """Parse and look up information for a phone number.

    Args:
        number: Phone number in E.164 format (e.g. +5511999998888).

    Returns:
        PhoneResult with all available metadata.
    """
    try:
        parsed = phonenumbers.parse(number)
    except phonenumbers.phonenumberutil.NumberParseException as exc:
        logger.warning(f"Could not parse {number!r}: {exc}")
        return PhoneResult(number=number, valid=False)

    valid = phonenumbers.is_valid_number(parsed)
    if not valid:
        return PhoneResult(number=number, valid=False)

    return PhoneResult(
        number=number,
        valid=True,
        location=geocoder.description_for_number(parsed, "pt"),
        carrier_name=carrier.name_for_number(parsed, "pt"),
        number_type=_TYPE_LABELS.get(phonenumbers.number_type(parsed), "Unknown"),
        country=phonenumbers.region_code_for_number(parsed) or "",
        national_format=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
        international_format=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
    )
