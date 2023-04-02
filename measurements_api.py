from dataclasses import dataclass
from datetime import timedelta, datetime
from typing import Optional, Any

import influxdb_client
import logging

from influxdb_client.client.exceptions import InfluxDBError
from influxdb_client.client.write_api import SYNCHRONOUS

logger = logging.getLogger(__name__)


@dataclass
class Measurement:
    measurement_name: str
    tags: dict
    value: float
    

class MeasurementsAPI:
    DEFAULT_ORG = 'dchouse'
    DEFAULT_BUCKET = 'dchouse'
    DEFAULT_URL = 'http://68.183.159.42:8086/'

    def __init__(
        self,
        token: str,
        url: Optional[str] = None,
        org: Optional[str] = None,
        bucket: Optional[str] = None
    ):
        self.token = token
        self.url = url or self.DEFAULT_URL
        self.org = org or self.DEFAULT_ORG
        self.bucket = bucket or self.DEFAULT_BUCKET

        self._client = influxdb_client.InfluxDBClient(
            url=self.url,
            token=self.token,
            org=self.org
        )
        self._write_api = self._client.write_api(write_options=SYNCHRONOUS)
        self.query_api = self._client.query_api()

    def send_measurement(
        self,
        m: Measurement,
    ):

        p = influxdb_client.Point(m.measurement_name)
        for tag_name, tag_value in m.tags.items():
            p = p.tag(tag_name, tag_value)

        p = p.field("value", m.value)

        try:
            self._write_api.write(
                bucket=self.bucket,
                org=self.org,
                record=p,
            )
        except InfluxDBError:
            import traceback
            e = traceback.format_exc()
            logger.error(e)
