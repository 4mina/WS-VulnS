from django.contrib import admin
from Attacks.models import Attack, DosAttack, InjAttack, XMLBombAttack, SQLiAttack, OversizedXMLAttack, OversizedPayloadAttack, XMLiAttack


class XMLBombAttackAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'name', 'family', 'type', 'payload')


admin.site.register(XMLBombAttack, XMLBombAttackAdmin)


class SQLiAttackAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'name', 'family', 'type', 'patterns')


admin.site.register(SQLiAttack, SQLiAttackAdmin)


class OversizedXMLAttackAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'name', 'family', 'type', 'payload')


admin.site.register(OversizedXMLAttack, OversizedXMLAttackAdmin)


class OversizedPayloadAttackAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'name', 'family', 'type', 'payload')


admin.site.register(OversizedPayloadAttack, OversizedPayloadAttackAdmin)


class XMLiAttackAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'name', 'family', 'type', 'patterns')


admin.site.register(XMLiAttack, XMLiAttackAdmin)


class AttackAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'name', 'family')


admin.site.register(Attack, AttackAdmin)


class DosAttackAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'name', 'family', 'payload')


admin.site.register(DosAttack, DosAttackAdmin)


class InjAttackAdmin(admin.ModelAdmin):
    empty_value_display = '-empty-'
    list_display = ('__str__', 'name', 'family', 'patterns')


admin.site.register(InjAttack, InjAttackAdmin)
