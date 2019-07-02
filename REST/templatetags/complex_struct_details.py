from django import template

from collections import Mapping
import json

register = template.Library()


@register.filter
def parameters_to_json(parameters):
    return json.dumps(parameters, indent=4, separators=(',', ': '))

