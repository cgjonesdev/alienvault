from django.conf.urls import url, include
from rest_framework import routers
import views


urlpatterns = [
    url(r'^$', views.APIRoot.as_view(), name='api_root'),
    url(r'^api/threat/ip/(?P<pk>.*$)',
        views.IPDetailsView.as_view(), name='threat_details'),
    url(r'^api/traffic',
        views.TrafficDetailsView.as_view(), name='traffic_details')
]