import hashlib
import uuid as uuid
from datetime import datetime, timedelta

import jwt
from django.conf import settings
from django.conf.global_settings import EMAIL_HOST_USER
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin
)
from django.core.mail import send_mail
from django.db import models
from django.template import Context, Template

from pytz import unicode
import random

from tinymce.models import HTMLField

from easyWallet.settings import MEDIA_ROOT


class UserManager(BaseUserManager):
    """
    Django требует, чтобы кастомные пользователи определяли свой собственный
    класс Manager. Унаследовавшись от BaseUserManager, мы получаем много того
    же самого кода, который Django использовал для создания User (для демонстрации).
    """

    def create_user(self, username, email, password=None, ref=None):
        """ Создает и возвращает пользователя с имэйлом, паролем и именем. """
        if username is None:
            raise TypeError('Users must have a username.')

        if email is None:
            raise TypeError('Users must have an email address.')

        salt = hashlib.sha1(str(random.random()).encode('utf8')).hexdigest()[:5]
        usernamesalt = username
        if isinstance(usernamesalt, unicode):
            usernamesalt = usernamesalt.encode('utf8')
        usernameemailsalt = username + email
        if isinstance(usernameemailsalt, unicode):
            usernameemailsalt = usernameemailsalt.encode('utf8')
        activation_key = hashlib.sha1(salt.encode('utf8') + usernameemailsalt).hexdigest()

        bot_uuid = hashlib.sha1(salt.encode('utf8') + usernamesalt).hexdigest()
        user = self.model(username=username,activation_key=activation_key,bot_uuid=bot_uuid,referral=ref, email=self.normalize_email(email))
        user.set_password(password)
        user.key_expires = datetime.strftime(datetime.now() + timedelta(days=2),
                                                         "%Y-%m-%d %H:%M:%S")


        user.save()
        code = 'C79WA' + str(user.id)
        code = code
        refCode = ReferralCode.objects.create(user=user, code=code, percent=15)
        refCode.save()

        user.save()

        #user.sendEmail()
        return user

    def create_superuser(self, username, email, password):
        """ Создает и возввращет пользователя с привилегиями суперадмина. """
        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

        return user


class User(AbstractBaseUser, PermissionsMixin):
    # Каждому пользователю нужен понятный человеку уникальный идентификатор,
    # который мы можем использовать для предоставления User в пользовательском
    # интерфейсе. Мы так же проиндексируем этот столбец в базе данных для
    # повышения скорости поиска в дальнейшем.
    username = models.CharField(db_index=True, max_length=255, unique=True)

    # Так же мы нуждаемся в поле, с помощью которого будем иметь возможность
    # связаться с пользователем и идентифицировать его при входе в систему.
    # Поскольку адрес почты нам нужен в любом случае, мы также будем
    # использовать его для входы в систему, так как это наиболее
    # распространенная форма учетных данных на данный момент (ну еще телефон).
    email = models.EmailField(db_index=True, unique=True)

    # Когда пользователь более не желает пользоваться нашей системой, он может
    # захотеть удалить свой аккаунт. Для нас это проблема, так как собираемые
    # нами данные очень ценны, и мы не хотим их удалять :) Мы просто предложим
    # пользователям способ деактивировать учетку вместо ее полного удаления.
    # Таким образом, они не будут отображаться на сайте, но мы все еще сможем
    # далее анализировать информацию.
    is_active = models.BooleanField(default=True)

    referral = models.IntegerField(null=True, blank=True)
    # Этот флаг определяет, кто может войти в административную часть нашего
    # сайта. Для большинства пользователей это флаг будет ложным.
    is_staff = models.BooleanField(default=False)
    two_factor = models.BooleanField(default=False, verbose_name='2FA')
    secret_code = models.CharField(max_length=40,default='')
    # Временная метка создания объекта.
    created_at = models.DateTimeField(auto_now_add=True)

    # Временная метка показывающая время последнего обновления объекта.
    updated_at = models.DateTimeField(auto_now=True)

    is_email_confirm = models.BooleanField(default=False)
    is_support = models.BooleanField(default=False)
    activation_key = models.CharField(max_length=40,default='')
    key_expires = models.DateTimeField()
    # Дополнительный поля, необходимые Django
    # при указании кастомной модели пользователя.
    bot_uuid = models.CharField(max_length=250, null=True, blank=True, verbose_name='Бот UUID')
    balance = models.FloatField(default=0, null=False, blank=True, verbose_name='Баланс')
    telegram = models.CharField(max_length=250, null=True, blank=True, verbose_name='Телеграм')
    referral = models.IntegerField(null=True, blank=True, verbose_name='ID Реферрала')
    ref_balance = models.CharField(max_length=250, null=True, blank=True, verbose_name='Реферальный баланс', default=0)
    # Свойство USERNAME_FIELD сообщает нам, какое поле мы будем использовать
    # для входа в систему. В данном случае мы хотим использовать почту.
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    # Сообщает Django, что определенный выше класс UserManager
    # должен управлять объектами этого типа.
    objects = UserManager()

    def __str__(self):
        """ Строковое представление модели (отображается в консоли) """
        return self.email

    @property
    def token(self):
        """
        Позволяет получить токен пользователя путем вызова user.token, вместо
        user._generate_jwt_token(). Декоратор @property выше делает это
        возможным. token называется "динамическим свойством".
        """
        return self._generate_jwt_token()

    def get_full_name(self):
        """
        Этот метод требуется Django для таких вещей, как обработка электронной
        почты. Обычно это имя фамилия пользователя, но поскольку мы не
        используем их, будем возвращать username.
        """
        return self.username

    def get_short_name(self):
        """ Аналогично методу get_full_name(). """
        return self.username

    def _generate_jwt_token(self):
        """
        Генерирует веб-токен JSON, в котором хранится идентификатор этого
        пользователя, срок действия токена составляет 1 день от создания
        """
        dt = datetime.now() + timedelta(days=1)

        token = jwt.encode({
            'id': self.pk,
            'exp': int(dt.timestamp())
        }, settings.SECRET_KEY, algorithm='HS256')

        return token.decode('utf-8')

    def sendEmail(self):
        link = "https://gctransfer.online/user/activate?key=" + self.activation_key
        c = Context({'activation_link': link, 'username': self.username})
        f = open(MEDIA_ROOT + '/email/email_confirm.txt', 'r', encoding="utf8")
        t = Template(f.read())
        f.close()
        message = t.render(c)
        # print unicode(message).encode('utf8')
        send_mail(EMAIL_HOST_USER, message, 'info@ecomtoday.vip', [self.email],
                  fail_silently=False)
    def sendNewPassword(self):
        chars = '+-/*!&$#?=@<>abcdefghijklnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
        length = 16
        password = ''
        for i in range(length):
            password += random.choice(chars)
        self.set_password(password)
        c = Context({'new_password': password, 'username': self.username})
        f = open(MEDIA_ROOT + '/email/new_password.txt', 'r', encoding="utf8")
        t = Template(f.read())
        f.close()
        message = t.render(c)
        # print unicode(message).encode('utf8')
        send_mail(EMAIL_HOST_USER, message, 'info@ecomtoday.vip', [self.email],
                  fail_silently=False)

        self.save()

class UserProject(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=250, verbose_name='Название проекта')


class UserTelegramChat(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    uuid = models.CharField(max_length=250, verbose_name='Чат ID')


class Currency(models.Model):
    name = models.CharField(max_length=15)
    code = models.CharField(max_length=5)


class CurrencyRate(models.Model):
    name = models.ForeignKey(Currency, on_delete=models.CASCADE, related_name='currency_in')
    name2 = models.ForeignKey(Currency, on_delete=models.CASCADE, related_name='currency_out')
    k = models.FloatField()
    last_update = models.DateTimeField()

    def __str__(self):
        return str(self.name) + ' - ' + str(self.name2) + ' (К = ' + str(self.k) + ' LAST UPDATE : ' + str(
            self.last_update) + ')'


class walletType(models.Model):
    name = models.CharField(max_length=250, verbose_name='Название')
    currency = models.ForeignKey(Currency, verbose_name='Название валюты', on_delete=models.CASCADE)

    class Meta:
        verbose_name = 'Тип кошелька'
        verbose_name_plural = 'Типы кошельков'

    def __str__(self):
        return str(self.name)


class Wallet(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='Пользователь')
    wallet_id = models.CharField(max_length=500, verbose_name='Номер кошелька')
    type = models.ForeignKey(walletType, on_delete=models.CASCADE, verbose_name='Тип кошелька')
    balance = models.FloatField(verbose_name='Баланс кошелька', null=True, blank=True)
    active = models.BooleanField(default=True, verbose_name='Активен')
    transfer_key = models.CharField(max_length=500, verbose_name='Ключ для перевода средств')
    callback = models.CharField(max_length=1000, verbose_name='Ссылка на колбэк', null=True, blank=True)
    count_confirmation = models.IntegerField(default=3, verbose_name='Количество подтверждений')
    icon = models.CharField(max_length=250, verbose_name='Иконка', null=True, blank=True)

    class Meta:
        verbose_name = 'Кошелек'
        verbose_name_plural = 'Кошельки'

    def __str__(self):
        return str(self.user) + ' ' + str(self.type)


class Address(models.Model):
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, verbose_name='Кошелек')
    input_address = models.CharField(max_length=500, verbose_name='Адрес')
    amount = models.FloatField(verbose_name='Сумма', null=True, blank=True)
    confirmation = models.BooleanField(default=False, verbose_name='Подтвержденный платеж')
    invoice_id = models.CharField(max_length=250, verbose_name='Номер заказа')
    secret = models.CharField(max_length=250, verbose_name='Секретный ключ')
    type = models.CharField(max_length=250, verbose_name='Тип адреса', null=True, blank=True)
    input_transaction_hash = models.CharField(max_length=500, verbose_name='Хэш входной транзакции', null=True,
                                              blank=True)
    created = models.DateTimeField(null=True, blank=True)
    project = models.ForeignKey(UserProject, on_delete=models.CASCADE, verbose_name='Проект', null=True, blank=True)

    class Meta:
        verbose_name = 'Адрес'
        verbose_name_plural = 'Адреса'

    def __str__(self):
        return str(self.wallet) + ' ' + str(self.input_address)


class Invoice(models.Model):
    STATUS = [
        (None, 'Укажи статус'),
        ('created', 'Создан'),
        ('paid', 'Оплачен'),
        ('failed', 'Ошибка'),
        ('canceled', 'Отменен'),

    ]

    TYPE = [
        (None, 'Укажи тип'),
        ('up', 'Поступление'),
        ('dw', 'Выплата'),
        ('change', 'Списание'),

    ]
    uuid = models.CharField(max_length=100, verbose_name='UUID')
    address = models.ForeignKey(Address, on_delete=models.CASCADE, verbose_name='Адрес')
    currency = models.ForeignKey(Currency, on_delete=models.CASCADE, verbose_name='Валюта приема')
    status = models.CharField(max_length=100, choices=STATUS, verbose_name='Статус')
    created = models.DateTimeField(auto_now_add=True, auto_created=True, editable=True)
    type = models.CharField(max_length=20, choices=TYPE, verbose_name='Тип счета')
    type_request = models.CharField(max_length=50, verbose_name='Тип заявки', null=True, blank=True)
    comment = models.TextField(max_length=2500, verbose_name='Комментарий', null=True, blank=True)

    class Meta:
        verbose_name = 'Счет'
        verbose_name_plural = 'Счета'

    def __str__(self):
        return str(self.uuid) + ' ' + str(self.currency)



class historyLogin(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='Пользователь')
    ip = models.CharField(max_length=500, verbose_name='IP Авторизации')
    date = models.DateTimeField(verbose_name='Дата авторизации')
    useragent = models.CharField(max_length=500, verbose_name='UserAgent')
    two_factor = models.BooleanField(verbose_name='2FA')
    created = models.DateTimeField(auto_now_add=True)


    class Meta:
        verbose_name = 'История авторизации'
        verbose_name_plural = 'История авторизций'

    def __str__(self):
        return str(self.user)


class UserNotification(models.Model):
    TYPES = [
        (None, 'Тип уведомления'),
        ("success", 'Успешно'),
        ('error', 'Ошибка'),
        ('warning', 'Предупреждение'),
        ('info', 'Инфо')
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    type = models.CharField(choices=TYPES,max_length=50, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    text = models.CharField(max_length=500, null=True, blank=True)
    read = models.BooleanField(default=False)


class ReferralCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='Пользователь', unique=True)
    code = models.CharField(verbose_name='Реферальный код', max_length=10, unique=True)
    percent = models.IntegerField(default=15, verbose_name='Процент')

    class Meta:
        verbose_name = 'Реферальный код'
        verbose_name_plural = 'Реферальные коды'

    def __str__(self):
        return 'Реферал ' + str(self.user)


class ReferralBalanceChange(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name='Пользователь')
    amount = models.FloatField(verbose_name='Реферальные бонусы')
    created = models.DateTimeField(auto_now_add=True)


    class Meta:
        verbose_name = 'Реферальный баланс'
        verbose_name_plural = 'Реферальный баланс'

    def __str__(self):
        return str(self.user)




class GeneralCategory(models.Model):
    name = models.CharField(max_length=250, verbose_name='Название категории')
    name_en = models.CharField(max_length=250, verbose_name='Название категории EN')
    icon = models.CharField(max_length=250, verbose_name='Иконка')
    slug = models.SlugField(verbose_name='URL')

    class Meta:
        verbose_name = 'Главная категория HelpCenter'
        verbose_name_plural = 'Главные категории HelpCenter'

    def __str__(self):
        return str(self.name)


class TwoLevelCategory(models.Model):
    general_category = models.ForeignKey(GeneralCategory, on_delete=models.CASCADE, verbose_name='Главная категория')
    text = models.CharField(max_length=500, verbose_name='Заголовок')
    text_en = models.CharField(max_length=500, verbose_name='Заголовок EN')

    class Meta:
        verbose_name = 'Категория второго уровня'
        verbose_name_plural = 'Категории второго уровня'

    def __str__(self):
        return str(self.text)


class HelpCenterBlock(models.Model):
    two_category = models.ForeignKey(TwoLevelCategory, on_delete=models.CASCADE, verbose_name='Категория')
    body = HTMLField(verbose_name='Текст блока')
    body_en = HTMLField(verbose_name='Текст блока EN')

    class Meta:
        verbose_name = 'Текстовый блок'
        verbose_name_plural = 'Текстовые блоки'

    def __str__(self):
        return 'Текстовый блок из категории - ' + str(self.two_category.text)


class HelpTiket(models.Model):
    STATUS = [
        (None, 'Статус'),
        ("new", 'Новый'),
        ('process', 'В процессе'),
        ('finish', 'Завершен')
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    user_project = models.ForeignKey(UserProject, on_delete=models.CASCADE, null=True, blank=True)
    title = models.CharField(max_length=250)
    urgency = models.CharField(max_length=100)
    body = models.TextField(max_length=1000)
    read = models.BooleanField(default=False)
    created = models.DateTimeField( auto_now_add=True)
    in_process = models.DateTimeField()
    in_finish = models.DateTimeField()


class HelpTiketFile(models.Model):
    tiket = models.ForeignKey(HelpTiket, on_delete=models.CASCADE)
    file_url = models.CharField(max_length=1000)


class HelpTiketMassage(models.Model):
    tiket = models.ForeignKey(HelpTiket, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    body = models.TextField(max_length=1000)
    read = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)



