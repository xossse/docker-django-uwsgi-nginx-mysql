import json

import requests
from django.db.models import Q
from django.forms import model_to_dict
from django.shortcuts import render
from rest_framework import permissions
from rest_framework import status
from rest_framework.decorators import permission_classes
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from coreWallet.models import *
from .renderers import UserJSONRenderer
from .serializers import LoginSerializer, RegistrationSerializer, UserSerializer

def home(request):
    return render(request, 'lk/index.html')
def room(request, room_name):
    return render(request, 'chat/room.html', {
        'room_name': room_name
    })

class Enable2FA(APIView):
    def post(self, request):
        password = request.data.get('password')
        user = request.user
        if user.check_password(password):
            user.two_factor = True
            salt = hashlib.sha1(str(random.random()).encode('utf8')).hexdigest()[:5]
            usernamesalt = user.username + str(user.id)
            if isinstance(usernamesalt, unicode):
                usernamesalt = usernamesalt.encode('utf8')
            user.secret_code = hashlib.sha1(salt.encode('utf8') + usernamesalt).hexdigest()
            user.save()
            return Response(
                {'status': 'ok', 'msg': '2FA Включено', 'msg_en': 'Success', 'error': ''},
                status=status.HTTP_200_OK)
        else:

            return Response(
                {'status': 'error', 'msg': 'Неправильный пароль', 'msg_en': 'Wrong password', 'error': ''},
                status=status.HTTP_200_OK)


class Disable2FA(APIView):
    def post(self, request):
        password = request.data.get('password')
        secret_code = request.data.get('secret_code')
        user = request.user
        if user.check_password(password) and user.secret_code == secret_code:
            user.two_factor = False
            user.save()
            return Response(
                {'status': 'ok', 'msg': '2FA Выключено', 'msg_en': 'Success', 'error': ''},
                status=status.HTTP_200_OK)
        else:

            return Response(
                {'status': 'error', 'msg': 'Неправильный пароль', 'msg_en': 'Wrong password', 'error': ''},
                status=status.HTTP_200_OK)


class Check2FA(APIView):
    def post(self, request):
        user = request.user
        if user.two_factor:
            return Response(
                {'status': 'ok', 'msg': '2FA Включено', 'msg_en': 'Success', 'error': ''},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {'status': 'error', 'msg': '2FA Выключен', 'msg_en': '2FA Disable', 'error': ''},
                status=status.HTTP_200_OK)


from html.parser import HTMLParser


class MyHTMLParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.recording = 0
        self.data = []

    def handle_data(self, data):
        self.data.append(data)


class GetQR2FA(APIView):
    def post(self, request):
        user = request.user
        TwoFAQr = 'https://www.authenticatorApi.com/pair.aspx?AppName=CryptCloud&AppInfo='+user.username+'&SecretCode='+ user.secret_code
        resp = requests.get(TwoFAQr).content
        data = str(resp).split('src')[1].split("'")[1]
        return Response(
            {'status': 'ok', 'msg': '2FA Включено', 'msg_en': 'Success', 'error': '','url': data, 'code': user.secret_code},
            status=status.HTTP_200_OK)


class CheckCurrect2FA(APIView):
    def post(self, request):
        pin = request.data.get('pincode')
        user = request.user
        response  = requests.get('https://www.authenticatorApi.com/Validate.aspx?Pin=' + pin + '&SecretCode=' + user.secret_code)
        if response.content.decode() == "True":
            return Response(
                {'status': 'ok', 'msg': '2FA Включено', 'msg_en': 'Success', 'error': ''},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {'status': 'error', 'msg': 'Неверный пинкод', 'msg_en': 'Wrong Pin', 'error': str(type(response.content)), '2':user.secret_code},
                status=status.HTTP_200_OK)


class HistoryLogin(APIView):
    def post(self, request):
        table = historyLogin.objects.filter(user=request.user).order_by('-created')[0:10]
        response = list()
        for item in table:
            data = {
                'ip': item.ip,
                'twoFA': item.two_factor,
                'created': item.created.strftime('%d.%m.%y %H:%M')
            }
            response.append(data)
        return Response(
            {'status': 'ok', 'table':response, 'msg_en': 'Success', 'error': ''},
            status=status.HTTP_200_OK)

class RefSystem(APIView):
    def get(self, request):
        data = ReferralCode.objects.get(user=request.user)
        return Response({'code':data.code,'percent': data.percent, 'ref_balance':request.user.ref_balance}, status=status.HTTP_200_OK)
class EmailConfirm(APIView):
    def get(self, request):
        activation_expired = False
        already_active = False
        key = request.GET.get('key')
        try:
            profile = User.objects.get(activation_key=key)
            if profile.is_email_confirm == False:
                if datetime.now() > profile.key_expires:
                    string = {'status': 'error', 'msg': 'Дата активации кода истекла. Отправьте новый запрос.'}
                else:  # Activation successful
                    profile.is_email_confirm = True
                    profile.save()
                    string = {'status': 'ok', 'msg': 'Почта успешно подтверждена'}

            # If user is already active, simply display error message
            else:
                string = {'status': 'ok', 'msg': 'Почта уже подтверждена'}
        except Exception as e:
            string = {'status': 'error', 'msg': 'Неверный ключ активации', 'error': str(e)}
        return Response(string, status=status.HTTP_200_OK)

class UserChangePassword(APIView):
    def post(self, request):
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        new_password2 = request.data.get('new_password2')
        user = request.user
        if new_password != new_password2:
            return Response({'status':'error', 'msg': 'Пароли не совпададют', 'msg_en': 'Passwords do not match', 'error': ''},status=status.HTTP_200_OK)

        if user.check_password(old_password):
            try:
                user.set_password(new_password)
                user.save()
                return Response({'status':'ok', 'msg': 'Пароль успешно изменен', 'msg_en': 'Successful password changes', 'error': ''},status=status.HTTP_200_OK)
            except Exception as error:

                return Response(
                    {'status': 'error', 'msg': 'Ошибка изменения пароля', 'msg_en': 'Password change error', 'error': error},status=status.HTTP_200_OK)
        else:
            return Response({'status':'error', 'msg': 'Неправильный старый пароль', 'msg_en': 'Wrong old password', 'error': ''},status=status.HTTP_200_OK)




class SendEmailConfirm(APIView):
    def get(self, request):
        try:
            user = request.user
            salt = hashlib.sha1(str(random.random()).encode('utf8')).hexdigest()[:5]
            usernamesalt = user.username
            if isinstance(usernamesalt, unicode):
                usernamesalt = usernamesalt.encode('utf8')
            activation_key = hashlib.sha1(salt.encode('utf8') + usernamesalt).hexdigest()
            user.activation_key = activation_key
            user.key_expires = datetime.strftime(datetime.now() + timedelta(days=2),
                                                 "%Y-%m-%d %H:%M:%S")
            user.save()
            user.sendEmail()
            string = {'status': 'ok', 'msg': 'Песьмо успешно оптравлено'}
        except Exception as e:
            string = {'status': 'error', 'msg': 'Не удалось отправить письмо, попробуйте позже', 'error': str(e)}

        return Response(string, status=status.HTTP_200_OK)



class SendEmailNewPassword(APIView):
    def post(self, request):
        try:
            email = request.data.get('email')
            user = User.objects.get(email=email)
            user.sendNewPassword()
            string = {'status': 'ok', 'msg': 'Письмо успешно оптравлено'}
        except Exception as e:
            string = {'status': 'error', 'msg': 'Не удалось отправить письмо, попробуйте позже', 'error': str(e)}

        return Response(string, status=status.HTTP_200_OK)


class CheckEmailConfirm(APIView):
    def get(self, request):
        user = request.user
        if user.is_email_confirm:
            string = {'status': "ok", 'msg': 'Почта подтверждена'}
        else:
            string = {'status': "error", 'msg': 'Почта не подтверждена'}

        return Response(string, status=status.HTTP_200_OK)


class RegistrationAPIView(APIView):
    """
    Разрешить всем пользователям (аутентифицированным и нет) доступ к данному эндпоинту.
    """
    permission_classes = (AllowAny,)
    serializer_class = RegistrationSerializer
    renderer_classes = (UserJSONRenderer,)

    def post(self, request):
        user = request.data.get('user', {})

        # Паттерн создания сериализатора, валидации и сохранения - довольно
        # стандартный, и его можно часто увидеть в реальных проектах.
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        ref_code = request.headers.get('referral_code')
        if ref_code:
            try:
                referral = ReferralCode.objects.get(code=ref_code).id

            except:
                print('error referral')
                referral = None
        else:
            referral = None
        user = User.objects.get(email=user.get('email'))
        user.referral = referral
        user.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class LoginAPIView(APIView):
    permission_classes = (AllowAny,)
    renderer_classes = (UserJSONRenderer,)
    serializer_class = LoginSerializer

    def post(self, request):
        user = request.data.get('user', {})

        # Обратите внимание, что мы не вызываем метод save() сериализатора, как
        # делали это для регистрации. Дело в том, что в данном случае нам
        # нечего сохранять. Вместо этого, метод validate() делает все нужное.
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        user = User.objects.get(email=user.get('email'))
        historyLog = historyLogin.objects.create(user=user, ip=request.META['REMOTE_ADDR'],
                                                 useragent=request.META['HTTP_USER_AGENT'],
                                                 date=datetime.now(), two_factor=user.two_factor)
        historyLog.save()
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserRetrieveUpdateAPIView(RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    renderer_classes = (UserJSONRenderer,)
    serializer_class = UserSerializer

    def retrieve(self, request, *args, **kwargs):
        # Здесь нечего валидировать или сохранять. Мы просто хотим, чтобы
        # сериализатор обрабатывал преобразования объекта User во что-то, что
        # можно привести к json и вернуть клиенту.
        serializer = self.serializer_class(request.user)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        serializer_data = request.data.get('user', {})

        # Паттерн сериализации, валидирования и сохранения - то, о чем говорили
        serializer = self.serializer_class(
            request.user, data=serializer_data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)


class GetWallets(APIView):
    def get(self, request):
        user = User.objects.get(id=1)
        wallets = Wallet.objects.filter(user=user, active=True)
        wallet_list = list()
        for wallet in wallets:
            data = list()
            data.append(wallet.wallet_id)
            wallet_list.append(data)
        return Response({'wallet_list': wallet_list}, status=status.HTTP_200_OK)


class GetBalanceWallet(APIView):
    def get(self, request):
        wallet_id = request.GET.get('wallet_id')
        balance = requests.get('https://apirone.com/api/v2/wallets/{}/balance'.format(wallet_id))
        available = balance.json().get('available')
        available = available / 100000000
        total = balance.json().get('total')
        total = total / 100000000
        wallet = Wallet.objects.get(wallet_id=wallet_id)
        wallet.balance = available
        wallet.save()
        return Response({'available': available, 'total': total}, status=status.HTTP_200_OK)


class GetTransaction(APIView):
    def get(self, request):
        wallet_id = request.GET.get('wallet_id')
        confirm = request.GET.get('confirm', None)
        wallet = Wallet.objects.get(wallet_id=wallet_id)
        if confirm is None:
            allTransactions = Address.objects.filter(wallet=wallet)
        else:
            allTransactions = Address.objects.filter(wallet=wallet, confirmation=True)
        allTransaction_list = list()
        for allTransaction in allTransactions:
            data = list()
            data.append(allTransaction.input_address)
            data.append(allTransaction.amount / 100000000)
            data.append(allTransaction.created.strftime('%d.%m.%Y'))
            allTransaction_list.append(data)

        return Response({'all': allTransaction_list}, status=status.HTTP_200_OK)


class CreateTransaction(APIView):
    def post(self, request):
        invoice_id = request.POST.get('invoice_id')
        wallet_id = request.POST.get('wallet_id')
        wallet = Wallet.objects.get(wallet_id=wallet_id)
        host = 'https://ecomtoday.vip/cryptoWallet/'
        callback = host + 'request/btc_callback'
        secret = "EnWM4f3IYIgz" + str(invoice_id)
        data = {
            "callback": {
                "url": callback,
                "data": {
                    "invoice_id": str(invoice_id),
                    "secret": secret
                }
            }
        }
        url = 'https://apirone.com/api/v2/wallets/{}/addresses'.format(wallet.wallet_id)
        response = requests.post(url, data=json.dumps(data))
        if response.status_code == 200:
            address = Address.objects.create(wallet=wallet, input_address=response.json().get('address'),
                                             invoice_id=invoice_id, secret=secret, created=datetime.now())
            try:
                address.save()
                invoice = Invoice.objects.create(address=address, uuid='INV-' + str(address.id),
                                                 currency=address.wallet.type, status='created')
                invoice.save()
                data = {'status': 'success', 'address': address.input_address}
            except:
                data = {'status': 'error', 'msg': "Ошибка при создании счета. Попробуйте позже."}
            return Response(data, status=status.HTTP_200_OK)


class CreateInvoice(APIView):
    def post(self, request):
        curancy = request.data.get('curancy')
        amount_usd = request.data.get('amount')
        amount = getCryptoAmount(curancy, amount_usd)
        wallet = Wallet.objects.get(type__currency__code=curancy, user=request.user)
        host = 'http://212.80.219.140:8080/'
        callback = host + 'request/'+ curancy.lower() +'_callback'
        invoice_id = 'INV-4921' + str(int(Address.objects.all().last().id) + int(1))
        secret = "EnWM4f3IYIgz" + str(invoice_id)
        data = {
            "callback": {
                "url": callback,
                "data": {
                    "invoice_id": str(invoice_id),
                    "secret": secret
                }
            }
        }
        url = 'https://apirone.com/api/v2/wallets/{}/addresses'.format(wallet.wallet_id)
        response = requests.post(url, data=json.dumps(data))
        if response.status_code == 200:
            address = Address.objects.create(wallet=wallet,amount=amount, input_address=response.json().get('address'),
                                             invoice_id=invoice_id, secret=secret, created=datetime.now(), project=UserProject.objects.get(user=request.user, name='Ручной счет'))
            try:
                address.save()
                invoice = Invoice.objects.create(address=address, uuid=invoice_id,type="up",
                                                 currency=address.wallet.type.currency, status='created')
                invoice.save()
                data = {'status': 'success', 'address': address.input_address, 'amount': amount,
                        'amount_usd':amount_usd, 'curancy': curancy, 'uuid':invoice_id[4:]}
            except Exception as e:
                data = {'status': 'error', 'msg': "Ошибка при создании счета. Попробуйте позже.", 'error': str(e)}
            return Response(data, status=status.HTTP_200_OK)

class BTCCallback(APIView):
    def post(self, request):
        address = Address.objects.get(input_address=request.data.get('input_address'))
        wallet = address.wallet
        confirmations = wallet.count_confirmation
        if int(request.data.get('confirmations')) >= confirmations:
            address.amount = request.data.get('value') / 100000000
            address.save()
            response = requests.post(wallet.callback, data=model_to_dict(address))
            if response.status_code == 200:
                if response.json().get('status') == '*ok*':
                    address.confirmation = True
                    address.save()
                    return Response('*ok*', status=status.HTTP_200_OK)
                else:
                    return Response('', status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response('', status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response('', status=status.HTTP_400_BAD_REQUEST)


@permission_classes((permissions.AllowAny,))
class GetWeekTrans(APIView):
    def post(self, request):
        user = request.user
        wallets = Wallet.objects.filter(user=user)
        today = datetime.now()
        print(today)
        day_ups = list()
        days = list()

        daysNum = 6
        i = 0
        while i <= daysNum:

            date_now = today - timedelta(daysNum - i)

            sumAmount = 0
            for wallet in wallets:

                addresses = Address.objects.filter(wallet=wallet,
                                                   created__gte=date_now.replace(hour=0, minute=0, second=0),
                                                   created__lte=date_now.replace(hour=23, minute=59, second=59),
                                                   confirmation=True)
                print(addresses)
                for address in addresses:
                    print(address.amount)
                    sumAmount += address.amount

            day_ups.append(str(sumAmount))
            print(day_ups)
            days.append(str(date_now.strftime('%d.%m')))
            i += 1
        string = {'days': days, 'sum': day_ups}

        return Response(string, status=status.HTTP_200_OK)


def getDayOfMouth(mouth, year):
    import calendar

    return calendar.monthrange(year, mouth)[1]


@permission_classes((permissions.AllowAny,))
class LastInvoices(APIView):
    def get(self, request):
        project = UserProject.objects.filter(user=request.user)
        addresses = Address.objects.filter(project__in=project).order_by('-created')
        invoices = Invoice.objects.filter(address__in=addresses, type='up').order_by('-created')[0:10]
        list_invoice = list()
        for item in invoices:
            data = {'id': item.id, 'project_uuid': item.address.project.name, 'uuid': item.uuid,
                    'currency': item.currency.name,
                    'amount_currency': item.address.amount, 'amount': getKeffCurancy(item.currency.name,item.address.amount),
                    'status': item.status.title(), 'created': item.created.strftime('%d.%m.%Y %H:%M'), }
            list_invoice.append(data)

        return Response(list_invoice, status=status.HTTP_200_OK)


@permission_classes((permissions.AllowAny,))
class LastAllInvoices(APIView):
    def get(self, request):
        start = request.GET.get('start')
        end = request.GET.get('end')
        currency = request.GET.get('currency')
        address = request.GET.get('q')
        start = datetime.fromisoformat(start)
        end = datetime.fromisoformat(end)
        start = start.combine(start.date(), start.min.time())
        end = end.combine(end.date(), end.max.time())
        project = UserProject.objects.filter(user=request.user)
        if currency !='All':

            if address:
                addresses = Address.objects.filter(project__in=project,created__gte=start, created__lte=end, wallet__type__currency__code=currency, input_address__icontains=address).order_by('-created')
            else:
                addresses = Address.objects.filter(project__in=project,created__gte=start, created__lte=end, wallet__type__currency__code=currency).order_by('-created')
        else:
            if address:
                addresses = Address.objects.filter(project__in=project,created__gte=start, created__lte=end, input_address__icontains=address).order_by('-created')
            else:
                addresses = Address.objects.filter(project__in=project,created__gte=start, created__lte=end).order_by('-created')
        invoices = Invoice.objects.filter(address__in=addresses).order_by('-created')
        list_invoice = list()
        for item in invoices:
            data = {'id': item.id, 'type': item.get_type_display(),
                    'coin': item.currency.name,'address': item.address.input_address,'transaction':item.uuid,

                    'project_uuid': item.address.project.name,
                    'amount': getKeffCurancy(item.currency.code, item.address.amount),
                    'amount_currency': item.address.amount,
                    'created': item.created.strftime('%d.%m.%Y %H:%M')}
            list_invoice.append(data)

        return Response(list_invoice, status=status.HTTP_200_OK)


@permission_classes((permissions.AllowAny,))
class StatInvoices(APIView):
    def get(self, request):
        start = datetime.today().replace(day=1)
        end = datetime.today()
        start = start.combine(start.date(), start.min.time())
        end = end.combine(end.date(), end.max.time())
        project = UserProject.objects.filter(user=request.user)
        addresses = Address.objects.filter(project__in=project)
        invoices = Invoice.objects.filter(address__in=addresses, type='up', created__gte=start, created__lte=end)
        total_invoice = invoices.count()
        paid_invoice = invoices.filter(status='paid').count()
        dont_paid_invoice = invoices.filter(status__in=['created', 'failed', 'canceled']).count()
        convert_invoice = round((paid_invoice / total_invoice) * 100, 2)
        all_wallet = Wallet.objects.filter(user=request.user)
        balance = 0
        for cur in all_wallet:
            balance += getUSDBalace(cur.type.name,getKeffCurancy(cur.type.currency.code, cur.balance))
        btc_balance = getBTCBalace(balance)
        data = {'total': total_invoice, 'paid': paid_invoice, 'dont_paid': dont_paid_invoice,
                'convert': convert_invoice, 'balance': round(balance, 2),'btc_balance': btc_balance}
        return Response(data, status=status.HTTP_200_OK)


@permission_classes((permissions.AllowAny,))
class Invoices(APIView):
    def get(self, request):
        date_in = request.GET.get('start')
        date_out = request.GET.get('end')
        inv_id = request.GET.get('inv_id')
        proj_name = request.GET.get('proj_name')
        currency = request.GET.get('currency')
        status_invoice = request.GET.get('status')

        query = ''
        if date_in:
            date_in = datetime.fromisoformat(date_in)
            date_in = date_in.combine(date_in.date(), date_in.min.time())

            if query == '':
                query = Q(created__gte=date_in)
            else:
                date_in = datetime.fromisoformat(date_in)
                date_in = date_in.combine(date_in.date(), date_in.min.time())
                query &= Q(created__gte=date_in)
        if date_out:

            if query == '':
                date_out = datetime.fromisoformat(date_out)
                date_out = date_out.combine(date_out.date(), date_out.max.time())
                query = Q(created__lte=date_out)
            else:

                date_out = datetime.fromisoformat(date_out)
                date_out = date_out.combine(date_out.date(), date_out.max.time())
                query &= Q(created__lte=date_out)
        if inv_id:

            if query == '':
                query = Q(uuid__icontains=inv_id)
            else:
                query &= Q(uuid__icontains=inv_id)
        if status_invoice:

            if query == '':
                query = Q(status=status_invoice)
            else:
                query &= Q(status=status_invoice)
        if currency:

            if currency != 'All':
                if query == '':
                    query = Q(currency__code=currency)
                else:
                    query &= Q(currency__code=currency)
        if proj_name:

            if query == '':
                query = Q(address__project__name__icontains=proj_name)
            else:
                query &= Q(address__project__name__icontains=proj_name)

        query &= Q(address__project__user=request.user)
        query &= Q(type='up')
        invoices = Invoice.objects.filter(query).order_by('-created')
        print(query)
        list_invoice = list()
        for item in invoices:
            """
            data = {'id': item.id, 'project_uuid': item.address.project.name, 'uuid': item.uuid,
                    'currency': item.currency.name,
                    'amount_currency': item.address.amount, 'amount': 20,
                    'status': item.status.title(), 'created': item.created.strftime('%d.%m.%Y %H:%M'), }
            """
            data = {'id': item.id, 'type': item.status,
                    'coin': item.currency.name,'address': item.address.input_address,'transaction':item.uuid,
                    'project_uuid': item.address.project.name,
                    'amount': getKeffCurancy(item.currency.code, item.address.amount),
                    'amount_currency': item.address.amount,
                    'created': item.created.strftime('%d.%m.%Y %H:%M')}
            list_invoice.append(data)

        return Response(list_invoice, status=status.HTTP_200_OK)

@permission_classes((permissions.AllowAny,))
class DWInvoices(APIView):
    def get(self, request):
        date_in = request.GET.get('start')
        date_out = request.GET.get('end')
        inv_id = request.GET.get('inv_id')
        proj_name = request.GET.get('proj_name')
        currency = request.GET.get('currency')
        status_invoice = request.GET.get('status')

        query = ''
        if date_in:
            date_in = datetime.fromisoformat(date_in)
            date_in = date_in.combine(date_in.date(), date_in.min.time())

            if query == '':
                query = Q(created__gte=date_in)
            else:
                date_in = datetime.fromisoformat(date_in)
                date_in = date_in.combine(date_in.date(), date_in.min.time())
                query &= Q(created__gte=date_in)
        if date_out:

            if query == '':
                date_out = datetime.fromisoformat(date_out)
                date_out = date_out.combine(date_out.date(), date_out.max.time())
                query = Q(created__lte=date_out)
            else:

                date_out = datetime.fromisoformat(date_out)
                date_out = date_out.combine(date_out.date(), date_out.max.time())
                query &= Q(created__lte=date_out)
        if inv_id:

            if query == '':
                query = Q(uuid__icontains=inv_id)
            else:
                query &= Q(uuid__icontains=inv_id)
        if status_invoice:

            if query == '':
                query = Q(status=status_invoice)
            else:
                query &= Q(status=status_invoice)
        if currency:
            if currency != 'All':
                if query == '':
                    query = Q(currency__code=currency)
                else:
                    query &= Q(currency__code=currency)
        if proj_name:

            if query == '':
                query = Q(address__project__name__icontains=proj_name)
            else:
                query &= Q(address__project__name__icontains=proj_name)

        query &= Q(address__project__user=request.user)
        query &= Q(type='dw')
        invoices = Invoice.objects.filter(query).order_by('-created')
        print(query)
        list_invoice = list()
        for item in invoices:
            """
            data = {'id': item.id, 'project_uuid': item.address.project.name, 'uuid': item.uuid,
                    'currency': item.currency.name,
                    'amount_currency': item.address.amount, 'amount': getKeffCurancy(item.currency.code, item.address.amount),
                    'status': item.status.title(), 'created': item.created.strftime('%d.%m.%Y %H:%M'), }
                    """
            data = {'id': item.id, 'type': item.status,
                    'coin': item.currency.name,'address': item.address.input_address,'transaction':item.uuid,
                    'project_uuid': item.address.project.name,
                    'amount': getKeffCurancy(item.currency.code, item.address.amount),
                    'amount_currency': item.address.amount,
                    'created': item.created.strftime('%d.%m.%Y %H:%M')}
            list_invoice.append(data)

        return Response(list_invoice, status=status.HTTP_200_OK)


@permission_classes((permissions.AllowAny,))
class DWStatInvoice(APIView):
    def get(self, request):


        query = Q(address__project__user=request.user)
        query &= Q(type='dw')
        invoices = Invoice.objects.filter(query).order_by('-created')
        print(query)
        list_invoice = list()
        amount_out_created = 0
        amount_all = 0
        for item in invoices.filter(status='created'):

            amount_out_created += getKeffCurancy(item.currency.code, item.address.amount)
        for item in invoices.filter(status='paid'):

            amount_all += getKeffCurancy(item.currency.code, item.address.amount)


        return Response({'amount_all': amount_all, 'amount_out_created':amount_out_created, 'amount_all_count': invoices.filter(status='paid').count(),
                         'amount_out_ctreated_count': invoices.filter(status='created').count()}, status=status.HTTP_200_OK)

@permission_classes((permissions.AllowAny,))
class Ba(APIView):
    def get(self, request):


        query = Q(address__project__user=request.user)
        query &= Q(type='dw')
        invoices = Invoice.objects.filter(query).order_by('-created')
        print(query)
        list_invoice = list()
        amount_out_created = 0
        amount_all = 0
        for item in invoices.filter(status='created'):

            amount_out_created += getKeffCurancy(item.currency.code, item.address.amount)
        for item in invoices.filter(status='paid'):

            amount_all += getKeffCurancy(item.currency.code, item.address.amount)


        return Response({'amount_all': amount_all, 'amount_out_created':amount_out_created, 'amount_all_count': invoices.filter(status='paid').count(),
                         'amount_out_ctreated_count': invoices.filter(status='created').count()}, status=status.HTTP_200_OK)



@permission_classes((permissions.AllowAny,))
class StatInvoicesInDate(APIView):
    def get(self, request):
        date_in = request.GET.get('date_in')
        date_out = request.GET.get('date_out')

        query = ''
        if date_in:
            date_in = datetime.fromisoformat(date_in)
            date_in = date_in.combine(date_in.date(), date_in.min.time())

            if query == '':
                query = Q(created__gte=date_in)
            else:
                date_in = datetime.fromisoformat(date_in)
                date_in = date_in.combine(date_in.date(), date_in.min.time())
                query &= Q(created__gte=date_in)
        if date_out:
            if query == '':
                date_out = datetime.fromisoformat(date_out)
                date_out = date_out.combine(date_out.date(), date_out.max.time())
                query = Q(created__lte=date_out)
            else:
                date_out = datetime.fromisoformat(date_out)
                date_out = date_out.combine(date_out.date(), date_out.max.time())
                query &= Q(created__lte=date_out)

        project = UserProject.objects.filter(user=request.user)
        addresses = Address.objects.filter(project__in=project)

        query &= Q(address__in=addresses)
        query &= Q(type='up')
        invoices = Invoice.objects.filter(query)
        string = ''
        try:
            balance_total = 0
            balance_paid = 0
            balance_unpaid = 0
            total_invoice = invoices.count()
            for item in invoices:
                balance_total += getKeffCurancy(item.currency.code, item.address.amount)
            paid_invoice = invoices.filter(status='paid').count()

            for item in invoices.filter(status='paid'):
                balance_paid += getKeffCurancy(item.currency.code, item.address.amount)
            dont_paid_invoice = invoices.filter(status__in=['created', 'failed', 'canceled']).count()

            for item in invoices.filter(status__in=['created', 'failed', 'canceled']):
                balance_unpaid += getKeffCurancy(item.currency.code, item.address.amount)
            convert_invoice = round((paid_invoice / total_invoice) * 100, 2)
        except Exception as e:
            total_invoice = 0
            paid_invoice = 0
            dont_paid_invoice = 0
            convert_invoice = 0
            string = str(e)
        data = {'total': total_invoice,'usd_total':balance_total, 'paid': paid_invoice,'usd_paid': balance_paid,'dont_paid': dont_paid_invoice,
                'convert': convert_invoice, 'usd_unpaid': balance_unpaid, 'error': string}
        return Response(data, status=status.HTTP_200_OK)


class GetAllCurrency(APIView):
    def get(self, request):
        all_cur = Currency.objects.all()

        list_cur = list()
        for cur in all_cur:
            data = {'code': cur.code, 'label': cur.name}
            list_cur.append(data)

        return Response(list_cur, status=status.HTTP_200_OK)


class GetAllBalance(APIView):

    def get(self, request):
        all_wallet = Wallet.objects.filter(user=request.user)
        balance = 0
        for cur in all_wallet:
            balance += getUSDBalace(cur.type.name,getKeffCurancy(cur.type.name,cur.balance))

        btc_balance = getBTCBalace(balance)
        return Response({'balance':round(balance, 2), 'btc_balance': btc_balance}, status=status.HTTP_200_OK)


class GetAllWallet(APIView):

    def get(self, request):
        all_wallet = Wallet.objects.filter(user=request.user)
        list_wallet = list()
        for cur in all_wallet:
            balance = getKeffCurancy(cur.type.currency.code, cur.balance)
            data = {'type': cur.type.name, 'icon': cur.icon,
                    'balance': balance,
                    'usd':getUSDBalace(cur.type.name,balance)}
            list_wallet.append(data)
        return Response(list_wallet, status=status.HTTP_200_OK)


def getKeffCurancy(val, amount):
    curancy_1 = Currency.objects.get(code='USD')
    curancy_2 = Currency.objects.get(code=val)
    try:
        currency_t = CurrencyRate.objects.get(name=curancy_1, name2=curancy_2)
    except:
        currency_t = CurrencyRate.objects.create(name=curancy_1, name2=curancy_2, k=1, last_update=datetime.now().replace(minute=0, hour=0, day=1))
        currency_t.save()
    if currency_t.last_update <= (datetime.now() - timedelta(minutes=20)):
        k = requests.get('https://apirone.com/api/v2/ticker?currency=' + val.lower()).json().get('usd')

        try:
            curs = CurrencyRate.objects.get(name=curancy_1, name2=curancy_2)
            curs.k = k

            curs.last_update = datetime.now()
            curs.save()
        except Exception as e:
            print(e)
            print('Не найдена валюта, и хуй с ней')

    currency_t = CurrencyRate.objects.get(name=curancy_1, name2=curancy_2)
    ammount_val = float(amount) * float(currency_t.k)
    if val == 'BTC':
        ammount_val = ammount_val
    else:
        ammount_val = round(ammount_val, 2)

    return round(ammount_val, 2)


def getBTCBalace( amount):
    val = 'BTC'
    curancy_1 = Currency.objects.get(code='USD')
    curancy_2 = Currency.objects.get(code="BTC")
    try:
        currency_t = CurrencyRate.objects.get(name=curancy_1, name2=curancy_2)
    except:
        currency_t = CurrencyRate.objects.create(name=curancy_1, name2=curancy_2, k=1, last_update=datetime.now().replace(minute=0, hour=0, day=1))
        currency_t.save()
    if currency_t.last_update <= (datetime.now() - timedelta(minutes=20)):
        k = requests.get('https://apirone.com/api/v2/ticker?currency=' + val.lower()).json().get('usd')

        try:
            curs = CurrencyRate.objects.get(name=curancy_1, name2=curancy_2)
            curs.k = k

            curs.last_update = datetime.now()
            curs.save()
        except Exception as e:
            print(e)
            print('Не найдена валюта, и хуй с ней')

    currency_t = CurrencyRate.objects.get(name=curancy_1, name2=curancy_2)
    ammount_val = float(amount) / float(currency_t.k)
    if val == 'BTC':
        ammount_val = ammount_val
    else:
        ammount_val = round(ammount_val, 6)

    return round(ammount_val, 2)

def getCryptoAmount(val, amount):
    curancy_1 = Currency.objects.get(code='USD')
    curancy_2 = Currency.objects.get(code="BTC")
    try:
        currency_t = CurrencyRate.objects.get(name=curancy_1, name2=curancy_2)
    except:
        currency_t = CurrencyRate.objects.create(name=curancy_1, name2=curancy_2, k=1, last_update=datetime.now().replace(minute=0, hour=0, day=1))
        currency_t.save()
    if currency_t.last_update <= (datetime.now() - timedelta(minutes=20)):
        k = requests.get('https://apirone.com/api/v2/ticker?currency=' + val.lower()).json().get('usd')

        try:
            curs = CurrencyRate.objects.get(name=curancy_1, name2=curancy_2)
            curs.k = k

            curs.last_update = datetime.now()
            curs.save()
        except Exception as e:
            print(e)
            print('Не найдена валюта, и хуй с ней')

    currency_t = CurrencyRate.objects.get(name=curancy_1, name2=curancy_2)
    ammount_val = float(amount) / float(currency_t.k)

    return round(ammount_val, 6)
def getUSDBalace(val, amount):
    curancy_1 = Currency.objects.get(code='USD')
    curancy_2 = Currency.objects.get(code=val)
    try:
        currency_t = CurrencyRate.objects.get(name=curancy_1, name2=curancy_2)
    except:
        currency_t = CurrencyRate.objects.create(name=curancy_1, name2=curancy_2, k=1, last_update=datetime.now().replace(minute=0, hour=0, day=1))
        currency_t.save()
    if currency_t.last_update <= (datetime.now() - timedelta(minutes=20)):
        k = requests.get('https://apirone.com/api/v2/ticker?currency=' + val.lower()).json().get('usd')

        try:
            curs = CurrencyRate.objects.get(name=curancy_1, name2=curancy_2)
            curs.k = k

            curs.last_update = datetime.now()
            curs.save()
        except Exception as e:
            print(e)
            print('Не найдена валюта, и хуй с ней')

    currency_t = CurrencyRate.objects.get(name=curancy_1, name2=curancy_2)
    ammount_val = float(amount) * float(currency_t.k)
    if val == 'BTC':
        ammount_val = ammount_val
    else:
        ammount_val = round(ammount_val, 6)

    return round(ammount_val, 2)


class InvoiceOutBal(APIView):
    def get(self, request):
        wallet = Wallet.objects.filter(user=request.user)

        bal = 0
        for cur in wallet:
            invoice_outs = Invoice.objects.filter(status='created', type='dw', address__wallet=cur)
            for item in invoice_outs:
                bal += item.address.amount

        return Response(bal, status=status.HTTP_200_OK)


class BalanceOut(APIView):
    def get(self, request):
        currency = request.GET.get('currency')
        wallet = Wallet.objects.filter(user=request.user, type__currency__code=currency)
        balance_usd = 0
        balance_crypto = 0
        bal = 0
        for cur in wallet:
            invoice_outs = Invoice.objects.filter(status='created',type='dw',  address__wallet=cur)
            for item in invoice_outs:
                bal += item.address.amount
            balance_usd += getKeffCurancy(cur.type.currency.code, cur.balance-bal)
            balance_crypto += cur.balance -bal
        data = {'usd': round(balance_usd,2), 'crypto': balance_crypto}
        return Response(data, status=status.HTTP_200_OK)

def AvilBalance(currency, user):
    wallet = Wallet.objects.filter(user=user, type__currency__code=currency)
    balance_usd = 0
    balance_crypto = 0
    bal = 0
    for cur in wallet:
        invoice_outs = Invoice.objects.filter(status='created', type='dw', address__wallet=cur)
        for item in invoice_outs:
            bal += item.address.amount
        balance_usd += getKeffCurancy(cur.type.currency.code, cur.balance - bal)
        balance_crypto += cur.balance - bal
    data = {'usd': round(balance_usd, 2), 'crypto': balance_crypto}

    return data

class InvoicesOut(APIView):
    """
    Класс отвечающий за создание заявки на вывод
    post - {'data':{'type': ('crypto' or 'fiat'), 'CurrencyOut': 'BTC' or other, 'CurrencyIn': 'BTC' or other,
            'AmountOut': amount in $, 'WalletAddressOut': any crypto address,'Comment': any string}}
        :return - {'status': 'ok' or 'error', 'data': {'inv_id': invoice uuid or null, 'error': any string error}}
    """

    def post(self, request):
        data = request.data.get('data', None)
        print(request.data)
        if data:
            type = data.get('type', None)
            CurrencyOut = data.get('CurrencyOut', None)
            AmountOut = data.get('AmountOut', 0)
            if type == 'Crypto':
                avilBal = AvilBalance(CurrencyOut, request.user).get('crypto')
            else:
                avilBal = AvilBalance(CurrencyOut, request.user).get('usd')

            if avilBal >= float(AmountOut):
                WalletAddressOut = data.get('WalletAddressOut', None)
                Comment = data.get('Comment')
                try:
                    wallet_out = Wallet.objects.filter(user=request.user, type__currency__code=CurrencyOut)[0]
                    address_out = Address.objects.create(wallet=wallet_out, input_address=WalletAddressOut, amount=AmountOut, invoice_id='#', secret="#"
                                                         ,created=datetime.now(), project=UserProject.objects.filter(user=request.user)[0])
                    address_out.save()
                    inv_out = Invoice.objects.create(uuid='INV-'+ str(address_out.id), address=address_out, currency=address_out.wallet.type.currency, status='created', created=datetime.now(), type='dw', type_request=type, comment=Comment )
                    inv_out.save()
                    string = {'status': 'ok', 'data':{'inv_id': inv_out.uuid, 'error': None}}
                except Exception as e:
                    string = {'status': 'error', 'data':{'inv_id': None, 'error': str(e)}}
            else:

                string = {'status': 'error', 'data': {'inv_id': None, 'error': "Сумма больше чем доступно"}}

        return Response(string, status=status.HTTP_200_OK)
