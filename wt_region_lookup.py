import json
from shapely.geometry import shape, Point
from rtree import index

# Lazy-loaded globals
_GEO_LOADED = False
_IDX = None
_SHAPES = None

def load_wt_geojson(path="watttime_regions.geojson"):
    """
    Loads the WattTime GeoJSON and builds a spatial index.
    This is called automatically on the first lookup.
    """
    global _GEO_LOADED, _IDX, _SHAPES

    if _GEO_LOADED:  # already loaded
        return

    with open(path, "r") as f:
        data = json.load(f)

    features = data["features"]
    _IDX = index.Index()
    _SHAPES = []

    for i, feature in enumerate(features):
        geom = shape(feature["geometry"])
        props = feature["properties"]
        region_name = props.get("region") or props.get("name")

        _SHAPES.append((region_name, geom))
        _IDX.insert(i, geom.bounds)

    _GEO_LOADED = True


def lookup_wt_region(lat, lon):
    """
    Returns the WattTime region string for a given lat/lon.
    """
    if not _GEO_LOADED:
        load_wt_geojson()

    point = Point(lon, lat)
    candidates = list(_IDX.intersection((point.x, point.y, point.x, point.y)))

    for i in candidates:
        region_name, geom = _SHAPES[i]
        if geom.contains(point):
            return region_name

    return None
