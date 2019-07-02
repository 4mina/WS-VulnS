from django.db import models
from Attacks.choices import ATTACK_NAMES, ATTACK_TYPES, SQLI_TYPES, XMLB_TYPES, OVERSIZED_XML_TYPES, \
    OVERSIZED_PAYLOAD_TYPES, XML_INJECTION_TYPES
from picklefield import fields


class Attack(models.Model):
    name = models.CharField(choices=ATTACK_NAMES, max_length=18)
    family = models.CharField(choices=ATTACK_TYPES, max_length=15)


class DosAttack(Attack):
    def __init__(self, *args, **kwargs):
        super(DosAttack, self).__init__(*args, **kwargs)
        self.family = 'DoS'

    # payload to be sent in malicious requests
    payload = models.TextField(editable=True, blank=True)
    average_reponse_delay = models.PositiveIntegerField(null=True)

    def detect_DoS(self):
        return True


class InjAttack(Attack):
    def __init__(self, *args, **kwargs):
        super(InjAttack, self).__init__(*args, **kwargs)
        self.family = 'Inj'
    patterns = fields.PickledObjectField(null=True)


class XMLBombAttack(DosAttack):
    def __init__(self, *args, **kwargs):
        super(XMLBombAttack, self).__init__(*args, **kwargs)
        self.family = 'DoS'
        self.name = 'XMLb'

    type = models.CharField(choices=XMLB_TYPES, max_length=35, null=True, blank=True)


class SQLiAttack(InjAttack):
    def __init__(self, *args, **kwargs):
        super(SQLiAttack, self).__init__(*args, **kwargs)
        self.family = 'Inj'
        self.name = 'SQLi'

    type = models.CharField(choices=SQLI_TYPES, max_length=35, blank=True)


class OversizedXMLAttack(DosAttack):
    def __init__(self, *args, **kwargs):
        super(OversizedXMLAttack, self).__init__(*args, **kwargs)
        self.family = 'DoS'
        self.name = 'OVSXML'

    type = models.CharField(choices=OVERSIZED_XML_TYPES, max_length=35, blank=True)


class OversizedPayloadAttack(DosAttack):
    def __init__(self, *args, **kwargs):
        super(OversizedPayloadAttack, self).__init__(*args, **kwargs)
        self.family = 'DoS'
        self.name = 'OVSPYLD'

    type = models.CharField(choices=OVERSIZED_PAYLOAD_TYPES, max_length=35, blank=True)


class XMLiAttack(InjAttack):
    def __init__(self, *args, **kwargs):
        super(XMLiAttack, self).__init__(*args, **kwargs)
        self.family = 'Inj'
        self.name = 'XMLi'

    type = models.CharField(choices=XML_INJECTION_TYPES, max_length=35, blank=True)

