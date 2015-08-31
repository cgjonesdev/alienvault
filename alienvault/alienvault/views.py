from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.reverse import reverse, reverse_lazy
from rest_framework import viewsets, status
from serializers import UserSerializer
from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import JSONParser
from django.utils.six import BytesIO
from threat import *
from serializers import *
from models import User
import time


class APIRoot(APIView):
    def get(self, request):
        return Response({
            'IP Details': reverse('api_root', request=request),
        })


class IPDetailsView(APIView):
    def get(self, request, *args, **kw):
        ip = kw.get('pk')
        kw['request'] = request
        ip_details_request = IPDetails(ip)
        result = DetailsSerializer(ip_details_request)
        if not request.session.get('alienvaultid'):
            traffic_details_request = TrafficDetails(request, ip)
            user = UserSerializer(traffic_details_request)
            user_serializer = UserSerializer(
                data=JSONParser().parse(
                    BytesIO(JSONRenderer().render(user.data))
                )
            )
            user_serializer.is_valid()
            user_serializer.save()
        response = Response(result.data, status=status.HTTP_200_OK)
        return response

class TrafficDetailsView(APIView):
    def get(self, request):
        users = User.objects.all()
        if users:
            user_serializer = UserSerializer(users, many=True)
            return Response(user_serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(
                {'Traffic Details': reverse('traffic_details', request=request)}
            )
