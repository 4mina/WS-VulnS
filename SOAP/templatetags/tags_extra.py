from django import template

import json
from collections import Mapping

register = template.Library()


@register.filter
def transform_parameters(parameters):
    keys_set = {'optional', 'max_occurrence'}
    transformed_dictionary = {}
    for key, value in parameters.items():
        if key not in keys_set:
            if isinstance(value, Mapping):
                if 'Enumeration' in value:
                    transformed_dictionary.update({key: 'Enumeration'})
                else:
                    transformed_dictionary[key] = transform_parameters(value)
            else:
                transformed_dictionary.update({key: value})
    return transformed_dictionary


@register.filter
def parameters_to_json(parameters):
    dictionary = transform_parameters(parameters)
    return json.dumps(dictionary, indent=4, separators=(',', ': '))

