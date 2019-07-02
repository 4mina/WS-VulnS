DATA_TYPES_LIST = [
    'string',
    'duration',
    'daytimeduration',
    'yearmonthduration',
    'datetime',
    'datetimestamp',
    'date',
    'time',
    'gyear',
    'gmonth',
    'gday',
    'gyearmonth',
    'gmonthday',
    'boolean',
    'int',
    'short',
    'byte',
    'float',
    'double',
    'decimal',
    'integer',
    'long',
    'negativeinteger',
    'nonnegativeinteger',
    'positiveinteger',
    'nonpositiveinteger',
    'unsignedlong',
    'unsignedint',
    'unsignedshort',
    'unsignedbyte',
    'notation',
    'qname',
    'anyuri',
    'base64binary',
    'hexbinary',
    'normalizedstring',
    'token',
    'language',
    'nmtoken',
    'nmtokens',
    'name',
    'ncname',
    'id',
    'idref',
    'idrefs',
    'entity',
    'entities'
]

NUMBER_TYPES_LIST = [
    'int',
    'short',
    'byte',
    'float',
    'double',
    'decimal',
    'integer',
    'long',
    'negativeinteger',
    'nonnegativeinteger',
    'positiveinteger',
    'nonpositiveinteger',
    'unsignedlong',
    'unsignedint',
    'unsignedshort',
    'unsignedbyte',
]

INTEGER_TYPES_LIST = [
    'int',
    'short',
    'byte',
    'integer',
    'long',
    'negativeinteger',
    'nonnegativeinteger',
    'positiveinteger',
    'nonpositiveinteger',
    'unsignedlong',
    'unsignedint',
    'unsignedshort',
    'unsignedbyte',
]

STRING_TYPES_LIST = [
    'string',
    'notation',
    'qname',
    'normalizedstring',
    'token',
    'language',
    'nmtoken',
    'nmtokens',
    'name',
    'ncname',
    'id',
    'idref',
    'idrefs',
    'entity',
    'entities'
]

DATE_TYPES_LIST = [
    'duration',
    'daytimeduration',
    'yearmonthduration',
    'datetime',
    'datetimestamp',
    'date',
    'time',
    'gyear',
    'gmonth',
    'gday',
    'gyearmonth',
    'gmonthday',
]

MISC_TYPES_LIST = [
    'boolean',
    'anyuri',
    'base64binary',
    'hexbinary',
]

# Strings
STRING_VALUES = ['This is a string', 'This is yet another string', 'Another one !', 'The last one']
LANGUAGE_VALUES = ['en', 'en-US', 'fr', 'fr-FR']
NAME_VALUES = ['name_1', 'name_2', 'name_3', 'name_4']
ID_VALUES = ['id_1', 'id_2', 'id_3', 'id_4']
ENTITY_VALUES = ['entity_1', 'entity_2', 'entity_3', 'entity_4']
NMTOKEN_VALUES = ['token_1', 'token_2', 'token_3', 'token_4']
IDREFS_VALUES = ['id_1 id_2', 'id_3 id_4']
ENTITIES_VALUES = ['entity_1 entity_2', 'entity_3 entity_4']
NMTOKENS_VALUES = ['token_1 token_2', 'token_3', 'token_4']

# Time
DURATION_VALUES = ['P2Y6M5DT12H35M30S', 'P1DT2H', 'P20M', 'PT20M']
DAYTIMEDURATION_VALUES = ['P1DT2H', 'PT20M', 'PT120M', 'P0DT1H']
YEARMONTHDURATION_VALUES = ['P2Y6M', 'P20M', 'P0Y20M', 'P0Y']

# Misc
BOOLEAN_VALUES = ['true', 'false']
HEXBINARY_VALUES = ['0FB8', '2AF3', '3F2504E04F89', '41D30305E82C3301']
FILE_VALUES = ['text', 'image', 'video']

# Numbers
MAX_LONG = 9223372036854775807
MIN_LONG = -9223372036854775808
MAX_UNSIGNED_LONG = 18446744073709551615
MAX_INT = 2147483647
MIN_INT = -2147483648
MAX_UNSIGNED_INT = 4294967295
MAX_SHORT = 32767
MIN_SHORT = -32768
MAX_UNSIGNED_SHORT = 65535
MAX_BYTE = 127
MIN_BYTE = -128
MAX_UNSIGNED_BYTE = 255
MAX_FLOAT = +3.4E+38
MIN_FLOAT = -3.4E+38
