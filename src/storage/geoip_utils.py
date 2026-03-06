import geoip2.database
import os
import random

GEOIP_DB_PATH = "data/GeoLite2-City.mmdb"

class GeoIPLookup:
    def __init__(self):
        self.reader = None
        if os.path.exists(GEOIP_DB_PATH):
            try:
                self.reader = geoip2.database.Reader(GEOIP_DB_PATH)
                print("[*] GeoIP: Database loaded successfully.")
            except Exception as e:
                print(f"[!] GeoIP: Error loading database: {e}")
        else:
            print("[!] GeoIP: GeoLite2-City.mmdb not found in data/. Using simulation mode.")

    def get_location(self, ip):
        """
        Returns (lat, lon, country_name) for a given IP.
        """
        # Handle Private/Internal IPs
        if ip.startswith(('10.', '192.168.', '172.16.', '127.')):
            # Simulating specific locations for internal dashboard demo
            return 37.7749, -122.4194, "Internal Network (SF)" # Default SF for demo

        if self.reader:
            try:
                response = self.reader.city(ip)
                return (
                    response.location.latitude,
                    response.location.longitude,
                    response.country.name
                )
            except Exception:
                pass
        
        # Simulation/Fallback Logic for Demo
        # Randomly assign locations if no DB is found to show the map working
        mock_locations = [
            (40.7128, -74.0060, "USA"),       # New York
            (51.5074, -0.1278, "UK"),         # London
            (35.6895, 139.6917, "Japan"),     # Tokyo
            (-33.8688, 151.2093, "Australia"), # Sydney
            (48.8566, 2.3522, "France"),      # Paris
            (55.7558, 37.6173, "Russia"),     # Moscow
            (-23.5505, -46.6333, "Brazil")    # Sao Paulo
        ]
        lat, lon, country = random.choice(mock_locations)
        return lat, lon, country

    def close(self):
        if self.reader:
            self.reader.close()
