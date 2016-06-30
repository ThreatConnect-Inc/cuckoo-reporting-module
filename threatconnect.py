import datetime
import re
import socket

import ipaddress

from threatconnect import ThreatConnect, ResourceType

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
    """Delivers indicators from analysis results to an instance of ThreatConnect."""

    def run(self, results):
        """Uploads indicators and incident via ThreatConnect SDK.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """

        api_access_id = self.options.api_access_id
        api_secret_key = self.options.api_secret_key
        api_default_org = self.options.api_default_org
        api_base_url = self.options.api_base_url

        target_source = self.options.target_source

        tc = ThreatConnect(api_access_id,
                           api_secret_key,
                           api_default_org,
                           api_base_url)

        incidents = tc.incidents()

        date_today = datetime.date.today().strftime('%Y%m%d')
        filename = results['target']['file']['name']
        title = 'Cuckoo Analysis {}: {}'.format(date_today, filename)
        incident = incidents.add(title, target_source)

        date_today_iso = datetime.datetime.now().isoformat()
        incident.set_event_date(date_today_iso)

        analysis_id = results['info']['id']
        incident.add_attribute('Analysis ID', analysis_id)

        report_link = 'http://cuckoo01.labs.tc/analysis/{}/'.format(analysis_id)
        incident.add_attribute('Report Link', report_link)

        try:
            incident.commit()
        except (RuntimeError) as e:
            raise CuckooReportError("Failed to commit incident: {}".format(e))

        incident.load_attributes()
        for attribute in incident.attributes:
            if attribute.type == 'Analysis ID' or attribute.type == 'Report Link':
                attribute.add_security_label('DO NOT SHARE')

        try:
            incident.commit()
        except (RuntimeError) as e:
            raise CuckooReportError("Failed to commit incident: {}".format(e))

        indicators = tc.indicators()

        for conn in results['network']['udp']:
            if not reserved_ip(conn['src']):
                indicator = indicators.add(conn['src'], target_source)
                indicator.associate_group(ResourceType.INCIDENTS, incident.id)
                try:
                    indicator.commit()
                except (RuntimeError) as e:
                    raise CuckooReportError("Failed to commit indicator: {}".format(e))
            if not reserved_ip(conn['dst']):
                indicator = indicators.add(conn['dst'], target_source)
                indicator.associate_group(ResourceType.INCIDENTS, incident.id)
                try:
                    indicator.commit()
                except (RuntimeError) as e:
                    raise CuckooReportError("Failed to commit indicator: {}".format(e))

        for conn in results['network']['http']:
            host = re.sub(':\d+', '', conn['host'])
            if ip(host):
                if not reserved_ip(host):
                    indicator = indicators.add(host, target_source)
                    indicator.associate_group(ResourceType.INCIDENTS, incident.id)
                    try:
                        indicator.commit()
                    except (RuntimeError) as e:
                        raise CuckooReportError("Failed to commit indicator: {}".format(e))
            indicator = indicators.add(conn['uri'], target_source)
            indicator.associate_group(ResourceType.INCIDENTS, incident.id)
            try:
                indicator.commit()
            except (RuntimeError) as e:
                raise CuckooReportError("Failed to commit indicator: {}".format(e))

        for conn in results['network']['tcp']:
            if not reserved_ip(conn['src']):
                indicator = indicators.add(conn['src'], target_source)
                indicator.associate_group(ResourceType.INCIDENTS, incident.id)
                try:
                    indicator.commit()
                except (RuntimeError) as e:
                    raise CuckooReportError("Failed to commit indicator: {}".format(e))
            if not reserved_ip(conn['dst']):
                indicator = indicators.add(conn['dst'], target_source)
                indicator.associate_group(ResourceType.INCIDENTS, incident.id)
                try:
                    indicator.commit()
                except (RuntimeError) as e:
                    raise CuckooReportError("Failed to commit indicator: {}".format(e))

        for host in results['network']['hosts']:
            if ip(host):
                if not reserved_ip(host):
                    indicator = indicators.add(host, target_source)
                    indicator.associate_group(ResourceType.INCIDENTS, incident.id)
                    try:
                        indicator.commit()
                    except (RuntimeError) as e:
                        raise CuckooReportError("Failed to commit indicator: {}".format(e))
            else:
                indicator = indicators.add(host, target_source)
                indicator.associate_group(ResourceType.INCIDENTS, incident.id)
                try:
                    indicator.commit()
                except (RuntimeError) as e:
                    raise CuckooReportError("Failed to commit indicator: {}".format(e))

        for conn in results['network']['dns']:
            indicator = indicators.add(conn['request'], target_source)
            indicator.associate_group(ResourceType.INCIDENTS, incident.id)
            try:
                indicator.commit()
            except (RuntimeError) as e:
                raise CuckooReportError("Failed to commit indicator: {}".format(e))
            for answer in conn['answers']:
                indicator = indicators.add(conn['request'], target_source)
                indicator.associate_group(ResourceType.INCIDENTS, incident.id)
                try:
                    indicator.commit()
                except (RuntimeError) as e:
                    raise CuckooReportError("Failed to commit indicator: {}".format(e))

        for domain in results['network']['domains']:
            if domain['ip']:
                if not reserved_ip(domain['ip']):
                    indicator = indicators.add(domain['ip'], target_source)
                    indicator.associate_group(ResourceType.INCIDENTS, incident.id)
                    try:
                        indicator.commit()
                    except (RuntimeError) as e:
                        raise CuckooReportError("Failed to commit indicator: {}".format(e))
            indicator = indicators.add(domain['domain'], target_source)
            indicator.associate_group(ResourceType.INCIDENTS, incident.id)
            try:
                indicator.commit()
            except (RuntimeError) as e:
                raise CuckooReportError("Failed to commit indicator: {}".format(e))

        if results['target']['category'] == 'file':
            file_data = results['target']['file']
            indicator = indicators.add(file_data['md5'], target_source)
            indicator.set_indicator(file_data['sha1'])
            indicator.set_indicator(file_data['sha256'])
            indicator.set_size(file_data['size'])
            fo_date = results['info']['started'][:10]
        indicator.add_file_occurrence(file_data['name'], fo_path=None, fo_date=fo_date)
            try:
                indicator.commit()
            except (RuntimeError) as e:
                raise CuckooReportError("Failed to commit indicator: {}".format(e))
