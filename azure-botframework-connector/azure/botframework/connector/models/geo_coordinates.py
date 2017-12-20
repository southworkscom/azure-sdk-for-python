# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class GeoCoordinates(Model):
    """GeoCoordinates (entity type: "https://schema.org/GeoCoordinates").

    :param elevation: Elevation of the location [WGS
     84](https://en.wikipedia.org/wiki/World_Geodetic_System).
    :type elevation: float
    :param latitude: Latitude of the location [WGS
     84](https://en.wikipedia.org/wiki/World_Geodetic_System).
    :type latitude: float
    :param longitude: Longitude of the location [WGS
     84](https://en.wikipedia.org/wiki/World_Geodetic_System).
    :type longitude: float
    :param type: The type of this object. Always set to GeoCoordinates.
    :type type: str
    :param name: Name of the location.
    :type name: str
    """

    _attribute_map = {
        'elevation': {'key': 'elevation', 'type': 'float'},
        'latitude': {'key': 'latitude', 'type': 'float'},
        'longitude': {'key': 'longitude', 'type': 'float'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, elevation=None, latitude=None, longitude=None, type=None, name=None):
        super(GeoCoordinates, self).__init__()
        self.elevation = elevation
        self.latitude = latitude
        self.longitude = longitude
        self.type = type
        self.name = name
