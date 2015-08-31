import urllib2
import json
import re
import calendar
import time
from uuid import uuid4

import requests

# Known bad: 69.43.161.174
# Known good: 8.8.8.8
# Find more examples at https://www.alienvault.com/open-threat-exchange/dashboard

class IPDetails(object):
    def __init__(self, ip):
        # Set default attr values
        self._id = ''
        self.address = ip
        self.is_error = False
        self.is_valid = False
        self.is_tracked = False
        self.reputation_val = 0
        self.activities = []
        self.first_activity = None
        self.last_activity = None
        self.activity_types = []
        self.city = ''
        self.country = ''
        self.organization = ''
        self.latitude = 0.0

        try:

            # If the ip is 4 complete octets, test for address validity
            if re.search(r'(\d.*)\.(\d.*)\.(\d.*)\.(\d.*)', self.address):
                octet_fields = re.search(
                    r'(\d.*)\.(\d.*)\.(\d.*)\.(\d.*)', self.address
                ).groups()
                octet_field_correct_sizes = [octet for octet in octet_fields
                                             if 1 <= len(octet) <= 3]
                octet_field_correct_ranges = [octet for octet in octet_fields
                                              if int(octet) in range(256)]
                self.is_valid = True
                if (
                    not self.address or
                    len(octet_fields) != 4 or
                    len(octet_field_correct_sizes) != 4 or
                    len(octet_field_correct_ranges) != 4
                ):
                    self.is_valid = False


            # Get data from external source in Repuation class
            data = Reputation.get_details(self.address)

            # Test for and set is_tracked attr
            self.is_tracked = True
            if not data or data == 'fetch_error':
                self.is_tracked = False

            # If data was received, set attrs
            if data:
                data = json.loads(data)
                self._id = data.get('_id').get('$id')
                self.reputation_val = data.get('reputation_val')
                activities = data.get('activities')
                self.activities = [
                    ({'name': activity.get('name'),
                      'first_date': activity.get('first_date').get('sec'),
                      'last_date': activity.get('last_date').get('sec')}
                     for activity in data.get('activities'))
                ]
                first_dates = [activity.get('first_date').get('sec') for
                               activity in activities]
                if first_dates:
                    self.first_activity = min(first_dates)
                else:
                    self.first_activity = None
                last_dates = [activity.get('first_date').get('sec') for
                               activity in activities]
                if last_dates:
                    self.last_activity = max(last_dates)
                else:
                    self.last_activity = None
                self.activity_types = enumerate(
                    [activity.get('name') for activity in activities]
                )
                self.city = data.get('city')
                self.country = data.get('country')
                self.organization = data.get('organization')
                self.latitude = data.get('latitude')
        except:
            self.is_error = True


class TrafficDetails():
    def __init__(self, request, ip):
        request.session['alienvaultid'] = str(uuid4()).split('-')[-1].upper()
        self.alienvaultid = request.session.get('alienvaultid')
        self.visits = [
            {'address': str(ip),
             'timestamp': int(time.time()),
             'endpoint': '/api/threat/ip/{}'.format(ip)}
        ]


class Reputation(object):
    @staticmethod
    def get_details(ip):
        if ip:
            try:
                url = (
                    'http://reputation.alienvault.com/panel/ip_json.php?ip={}'
                    .format(ip)
                )
                return requests.get(url).text
            except:
                return 'fetch_error'
        else:
            return None
