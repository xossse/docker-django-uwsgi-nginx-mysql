from django.contrib import admin

# Register your models here.
from django.contrib.admin import ModelAdmin

from coreWallet.models import *




class CurrencyRateAdmin(ModelAdmin):
    list_display = ['name', 'name2', 'k', 'last_update']
    search_fields = ['name', 'name2']


admin.site.register(CurrencyRate, CurrencyRateAdmin)

admin.site.register(User)
admin.site.register(UserProject)
admin.site.register(UserTelegramChat)
admin.site.register(Invoice)
admin.site.register(Currency)
admin.site.register(historyLogin)
admin.site.register(ReferralCode)

class walletTypeAdmin(ModelAdmin):
    list_display = ['name', 'currency']


admin.site.register(walletType, walletTypeAdmin)


class WalletAdmin(ModelAdmin):
    list_display = ['user', 'wallet_id', 'type', 'balance', 'active']

    search_fields = ['wallet_id', 'user__user__username', 'user__telegram']


admin.site.register(Wallet, WalletAdmin)


class AddressAdmin(ModelAdmin):
    list_display = ['wallet', 'input_address', 'amount', 'confirmation', 'invoice_id']

    search_fields = ['wallet__wallet_id', 'wallet__user__user__username', 'wallet__user__telegram', 'input_address',
                     'invoice_id']


admin.site.register(Address, AddressAdmin)
