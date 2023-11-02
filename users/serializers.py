from django.conf import settings
from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import gettext as _
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from dj_rest_auth.registration.serializers import RegisterSerializer
from phonenumber_field.serializerfields import PhoneNumberField
from .models import Job


from .exceptions import (
    AccountNotRegisteredException,
    InvalidCredentialsException,
    AccountDisabledException,
)
from .models import PhoneNumber


User = get_user_model()


class UserRegistrationSerializer(RegisterSerializer):
    """
    Serializer for registrating new users using email or phone number.
    """
    username = serializers.CharField(required=False)
    phone_number = PhoneNumberField(
        required=False,
        write_only=True,
        validators=[
            UniqueValidator(
                queryset=PhoneNumber.objects.all(),
                message=_(
                    "A user is already registered with this phone number."),
            )
        ],
    )
    email = serializers.EmailField(required=False)

    def validate(self, validated_data):
        email = validated_data.get('email', None)
        phone_number = validated_data.get('phone_number', None)
        username = validated_data.get('username', None)

        if not (email, username or phone_number):
            raise serializers.ValidationError(
                _("Enter an email or a phone number."))

        if validated_data['password1'] != validated_data['password2']:
            raise serializers.ValidationError(
                _("The two password fields didn't match."))

        return validated_data

    def get_cleaned_data_extra(self):
        return {
            'phone_number': self.validated_data.get('phone_number', ''),
        }

    def create_phone(self, user, validated_data):
        phone_number = validated_data.get("phone_number")

        if phone_number:
            PhoneNumber.objects.create(user=user, phone_number=phone_number)
            user.phone.save()

    def custom_signup(self, request, user):
        self.create_phone(user, self.get_cleaned_data_extra())


from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import gettext as _
from rest_framework import serializers
from dj_rest_auth.registration.serializers import RegisterSerializer
from phonenumber_field.serializerfields import PhoneNumberField

from .exceptions import (
    AccountNotRegisteredException,
    InvalidCredentialsException,
    AccountDisabledException,
)
from .models import PhoneNumber

User = get_user_model()

class UserLoginSerializer(serializers.Serializer):
    """
    Serializer to login users with email, phone number, or username.
    """
    phone_number = PhoneNumberField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    username = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def _validate_phone_email_username(self, phone_number, email, username, password):
        user = None

        if email and password:
            user = authenticate(username=email, password=password)
        elif str(phone_number) and password:
            user = authenticate(username=str(phone_number), password=password)
        elif username and password:
            user = authenticate(username=username, password=password)
        else:
            raise serializers.ValidationError(_("Enter a phone number, email, or username and password."))

        return user

    def validate(self, validated_data):
        phone_number = validated_data.get('phone_number')
        email = validated_data.get('email')
        password = validated_data.get('password')
        username = validated_data.get('username')

        user = self._validate_phone_email_username(phone_number, email, username, password)

        if not user:
            raise InvalidCredentialsException()

        if not user.is_active:
            raise AccountDisabledException()

        # Email-specific checks
        if email:
            email_address = user.emailaddress_set.filter(email=user.email).exists()
            if not email_address:
                raise serializers.ValidationError(_('E-mail is not verified.'))

        validated_data['user'] = user
        return validated_data


class PhoneNumberSerializer(serializers.ModelSerializer):
    """
    Serializer class to serialize phone number.
    """
    phone_number = PhoneNumberField()

    class Meta:
        model = PhoneNumber
        fields = ('phone_number',)

    def validate_phone_number(self, value):
        try:
            queryset = User.objects.get(phone__phone_number=value)
            if queryset.phone.is_verified == True:
                err_message = _('Phone number is already verified')
                raise serializers.ValidationError(err_message)

        except User.DoesNotExist:
            raise AccountNotRegisteredException()

        return value


class VerifyPhoneNumberSerialzier(serializers.Serializer):
    """
    Serializer class to verify OTP.
    """
    phone_number = PhoneNumberField()
    otp = serializers.CharField(max_length=settings.TOKEN_LENGTH)

    def validate_phone_number(self, value):
        queryset = User.objects.filter(phone__phone_number=value)
        if not queryset.exists():
            raise AccountNotRegisteredException()
        return value

    def validate(self, validated_data):
        phone_number = str(validated_data.get('phone_number'))
        otp = validated_data.get('otp')

        queryset = PhoneNumber.objects.get(phone_number=phone_number)

        queryset.check_verification(security_code=otp)

        return validated_data


class JobSerializer(serializers.Serializer):
    class Meta:
        model = Job
        fields = '__all__'
