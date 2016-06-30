# Copyright 2016 ThreatConnect, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#      http://www.apache.org/licenses/LICENSE-2.0
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
"""
ThreatConnect reporting module for Cuckoo version 1.2.

This module creates an incident in ThreatConnect representing the analysis, and then imports all
network indicators found by Cuckoo and associates those indicators with the analysis.
"""

import datetime
import re
import socket

import ipaddress

import threatconnect

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError


def ip(indicator):
    """Check if an indicator is an IP address or not."""
    try:
        socket.inet_aton(indicator)
    except socket.error:
        return False
    else:
        return True


def reserved_ip(ip):
    """Check if an IP address is a reserved address or not."""
    ip_int = int(ipaddress.IPv4Address(unicode(ip)))
    if (ip_int <= 16777215 or
            167772160 <= ip_int <= 184549375 or
            1681915904 <= ip_int <= 1686110207 or
            2130706432 <= ip_int <= 2147483647 or
            2851995648 <= ip_int <= 2852061183 or
            2886729728 <= ip_int <= 2887778303 or
            3221225472 <= ip_int <= 3221225727 or
            3221225984 <= ip_int <= 3221226239 or
            3227017984 <= ip_int <= 3227018239 or
            3232235520 <= ip_int <= 3232301055 or
            3323068416 <= ip_int <= 3323199487 or
            3325256704 <= ip_int <= 3325256959 or
            3405803776 <= ip_int <= 3405804031 or
            3758096384 <= ip_int <= 4026531839 or
            4026531840 <= ip_int <= 4294967294 or
            ip_int == 4294967295):
        return True
    else:
        return False


class ThreatConnectReport(Report):
    """Reports indicators from analysis results to an instance of ThreatConnect."""

    def create_incident(self):
        """Create an incident to represent the analysis in ThreatConnect.

        @raise CuckooReportError: if fails to write report.
        """

        # Instantiate an incidents object
        incidents = self.tc.incidents()

        # Get todays date and the filename of the analysis target
        date_today = datetime.date.today().strftime('%Y%m%d')
        if self.results.get('target').get('file').get('name'):
            filename = self.results['target']['file']['name']

        # Build a title for the incident
        title = 'Cuckoo Analysis {}: {}'.format(date_today, filename)

        # Add the title to the object
        incident = incidents.add(title, self.target_source)

        # Get the full timestamp for the current time and set the event date
        date_today_iso = datetime.datetime.now().isoformat()
        incident.set_event_date(date_today_iso)

        # Add the analysis ID to an attribute
        if self.results.get('info').get('id'):
            analysis_id = self.results.get('info').get('id')
        incident.add_attribute('Analysis ID', analysis_id)

        # Build a report link and record it in the Source attribute
        report_link = self.report_link_template.format(analysis_id)
        incident.add_attribute('Source', report_link)

        # Commit the changes to ThreatConnect
        try:
            incident.commit()
        except RuntimeError as e:
            raise CuckooReportError('Failed to commit incident: {}'.format(e))

        # Load the attributes into the incident object
        incident.load_attributes()

        # Mark all Cuckoo attributes with DO NOT SHARE security label
        for attribute in incident.attributes:
            if attribute.type == 'Analysis ID' or attribute.type == 'Source':
                attribute.add_security_label('DO NOT SHARE')

        # Commit the changes to ThreatConnect
        try:
            incident.commit()
        except RuntimeError as e:
            raise CuckooReportError('Failed to commit incident: {}'.format(e))
        else:
            return incident.id

    def upload_indicator(self, raw_indicator):
        """Upload one indicator to ThreatConnect."""
        indicators = self.tc.indicators()
        indicator = indicators.add(raw_indicator, self.target_source)
        indicator.associate_group(threatconnect.ResourceType.INCIDENTS, self.incident_id)

        # Commit the changes to ThreatConnect
        try:
            indicator.commit()
        except RuntimeError as e:
            if not re.search('exclusion list', e):
                raise CuckooReportError('Failed to commit indicator: {}'.format(e))

    def import_network(self, type):
        """Loop through all connections and import all source and destination indicators.

        @param incident_id: Analysis incident ID.
        @param type: protocol, tcp or udp
        @raise CuckooReportError: if fails to write indicator.
        """
        for conn in self.results.get('network', dict()).get(type, dict()):

            # Import the source
            if not reserved_ip(conn.get('src')):
                self.upload_indicator(conn.get('src'))

            # Import the destination
            if not reserved_ip(conn.get('dst')):
                self.upload_indicator(conn.get('dst'))

    def import_network_http(self):
        """Loop through all HTTP network connections and import all HTTP indicators.

        @param incident_id: Analysis incident ID.
        @raise CuckooReportError: if fails to write indicator.
        """
        # Loop through all HTTP network connections
        for conn in self.results.get('network', dict()).get('http', dict()):

            # Remove port number from host
            host = re.sub(':\d+', '', conn.get('host'))

            # Check if the host is an IP address
            if ip(host):

                # Check if the IP address is reserved
                if not reserved_ip(host):
                    self.upload_indicator(host)

            # Import the URL indicator
            if conn.get('uri'):
                self.upload_indicator(conn.get('uri'))

    def import_network_hosts(self):
        """Loop through all network hosts and import all network host indicators.

        @param incident_id: Analysis incident ID.
        @raise CuckooReportError: if fails to write indicator.
        """
        for host in self.results.get('network', dict()).get('hosts', dict()):

            # Check if the host is an IP address
            if ip(host):

                # Check if the IP address is reserved
                if not reserved_ip(host):
                    self.upload_indicator(host)

            else:
                self.upload_indicator(host)

    def import_network_dns(self):
        """Loop through all DNS connections and import all request and answer indicators.

        @param incident_id: Analysis incident ID.
        @raise CuckooReportError: if fails to write indicator.
        """
        # Loop through all DNS request connections
        for conn in self.results.get('network', dict()).get('dns', dict()):

            # Record the DNS request
            self.upload_indicator(conn.get('request'))

            # Record all the answers
            for answer in conn.get('answers', list()):
                self.upload_indicator(answer)

    def import_network_domains(self):
        """Loop through all domains and import everything as host and address indicators.

        @param incident_id: Analysis incident ID.
        @raise CuckooReportError: if fails to write indicator.
        """
        for domain in self.results.get('network', dict()).get('domains', dict()):

            # If an IP is available, import it
            if domain.get('ip'):
                if not reserved_ip(domain.get('ip')):
                    self.upload_indicator(domain.get('ip'))

            # If domain is available, import it
            if domain.get('domain'):
                self.upload_indicator(domain.get('domain'))

    def import_file(self):
        """Import file indicator.

        @param incident_id: Analysis incident ID.
        @raise CuckooReportError: if fails to write indicator.
        """
        if self.results.get('target').get('category') == 'file':
            if self.results.get('target').get('file'):

                indicators = self.tc.indicators()

                file_data = self.results.get('target').get('file')

                # Import all the hashes
                indicator = indicators.add(file_data.get('md5'), self.target_source)
                indicator.set_indicator(file_data.get('sha1'))
                indicator.set_indicator(file_data.get('sha256'))

                # Set the file size
                indicator.set_size(file_data.get('size'))

                # If there is a started time, set this as a file occurrence along with the filename
                if self.results.get('info').get('started'):
                    fo_date = self.results.get('info').get('started')[:10]
                    indicator.add_file_occurrence(file_data.get('name'), fo_date=fo_date)

                indicator.associate_group(threatconnect.ResourceType.INCIDENTS, self.incident_id)

                # Commit the changes to ThreatConnect
                try:
                    indicator.commit()
                except RuntimeError as e:
                    if not re.search('exclusion list', e):
                        raise CuckooReportError('Failed to commit indicator: {}'.format(e))

    def run(self, results):
        """Upload indicators and incident via ThreatConnect SDK.

        @param results: Cuckoo results dict.
        """
        api_access_id = self.options.api_access_id
        api_secret_key = self.options.api_secret_key
        api_base_url = self.options.api_base_url
        self.target_source = self.options.target_source
        self.tc = threatconnect.ThreatConnect(api_access_id, api_secret_key,
                                              self.options.target_source, api_base_url)
        self.report_link_template = self.options.report_link_template
        self.results = results

        self.incident_id = self.create_incident()

        self.import_network('udp')
        self.import_network('tcp')
        self.import_network_http()
        self.import_network_hosts()
        self.import_network_dns()
        self.import_network_domains()
        self.import_file()
