from rest_framework import serializers
from models import User
from threat import IPDetails


class UserSerializer(serializers.Serializer):
    class Meta:
        model = User

    alienvaultid = serializers.CharField()
    visits = serializers.CharField()

    def create(self, validated_data):
        return User.objects.create(**validated_data)


class DetailsSerializer(serializers.Serializer):
    _id = serializers.CharField()
    is_error = serializers.NullBooleanField()
    is_valid = serializers.NullBooleanField()
    is_tracked = serializers.NullBooleanField()
    address = serializers.IPAddressField()
    reputation_val = serializers.IntegerField()
    activities = serializers.ListField()
    first_activity = serializers.IntegerField()
    last_activity = serializers.IntegerField()
    activity_types = serializers.ListField()
    city = serializers.CharField()
    country = serializers.CharField()
    organization = serializers.CharField()
    latitude = serializers.FloatField()
