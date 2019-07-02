import magic
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator

from WebService.choices import VALID_MIME_TYPES


def validate_description_url(value):
    description_url_validator = URLValidator(message='URL non valide', code='url_invalide')
    try:
        description_url_validator(value)
    except:
        raise ValidationError(message='URL non valide', code='url_invalide')


def validate_url_extension(value):
    if (not value.endswith("wsdl")) & (not value.endswith("WSDL")) & (not value.endswith("yaml")) & (not value.endswith("yml")):
        raise ValidationError(message='Type de fichier incorrect', code="invalid_file_extension")


def validate_description_file(value):
    file_name = value.name
    if (not file_name.endswith("wsdl")) & (not file_name.endswith("WSDL")) & (not file_name.endswith("yaml")) & (not file_name.endswith("yml")):
        raise ValidationError(message='Type de fichier incorrect', code="invalid_file_extension")
    # check that even if the extension is good the content could be other that just "text"
    file_type = magic.from_buffer(value.file.read(1024), mime=True)
    if file_type not in VALID_MIME_TYPES:
        raise ValidationError(message='Type de fichier incorrect', code="invalid_file_mime_type")