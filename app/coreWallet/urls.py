"""easyWallet URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from django.urls import path

from coreWallet import views
from coreWallet.views import UserRetrieveUpdateAPIView, RegistrationAPIView, LoginAPIView, CheckEmailConfirm, \
    SendEmailConfirm, EmailConfirm, UserChangePassword, SendEmailNewPassword, Enable2FA, Check2FA, GetQR2FA, \
    CheckCurrect2FA, Disable2FA, HistoryLogin, RefSystem

urlpatterns = [

    path('<str:room_name>/', views.room, name='room'),
    path('user', UserRetrieveUpdateAPIView.as_view()),
    path('users/', RegistrationAPIView.as_view()),

    path('users/activate', EmailConfirm.as_view()),
    path('users/change_password', UserChangePassword.as_view()),
    path('users/reset_password', SendEmailNewPassword.as_view()),
    path('users/send_confirm', SendEmailConfirm.as_view()),
    path('users/check_confirm', CheckEmailConfirm.as_view()),
    path('users/login/', LoginAPIView.as_view()),
    path('users/enable2fa/', Enable2FA.as_view()),
    path('users/disable2fa/', Disable2FA.as_view()),
    path('users/check2fa/', Check2FA.as_view()),
    path('users/get_qr_2fa/', GetQR2FA.as_view()),
    path('users/check_pin/', CheckCurrect2FA.as_view()),
    path('users/history_login/', HistoryLogin.as_view()),
    path('users/get_ref_code/', RefSystem.as_view()),
    path('wallet/btc_callback', views.BTCCallback.as_view()),
    path('wallet/getWallets', views.GetWallets.as_view()),
    path('wallet/getBalanceWallet', views.GetBalanceWallet.as_view()),
    path('wallet/getTransaction', views.GetTransaction.as_view()),
    path('wallet/createTransaction', views.CreateTransaction.as_view()),
    path('wallet/week_trans', views.GetWeekTrans.as_view()),
    path('wallet/last_invoice', views.LastInvoices.as_view()),
    path('wallet/last_all_invoice', views.LastAllInvoices.as_view()),
    path('wallet/stat_invoice', views.StatInvoices.as_view()),
    path('wallet/stat_invoice_in_date', views.StatInvoicesInDate.as_view()),
    path('wallet/invoices', views.Invoices.as_view()),
    path('wallet/invoices_dw', views.DWInvoices.as_view()),
    path('wallet/getallcurrency', views.GetAllCurrency.as_view()),
    path('wallet/getallbalance', views.GetAllBalance.as_view()),
    path('wallet/getallwallet', views.GetAllWallet.as_view()),
    path('wallet/balanceout', views.BalanceOut.as_view()),
    path('wallet/invoicesout', views.InvoicesOut.as_view()),
    path('wallet/invoicesoutbalance', views.InvoiceOutBal.as_view()),
    path('wallet/status_invoice_dw', views.DWStatInvoice.as_view()),
    path('wallet/create_invoice', views.CreateInvoice.as_view()),


]
