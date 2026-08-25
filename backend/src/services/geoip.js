/**
 * GeoIP enrichment for the Threat Map.
 *
 * When a GeoLite2 .mmdb database path is configured (GEOIP_MMDB), every
 * ingested alert gets a `geo` object attached:
 *
 *   geo: { country: "US", city: "Ashburn", lat: 39.0, lon: -77.5, asn: "AS15169" }
 *
 * The module degrades gracefully: with no path, a missing file, or an
 * unreadable database the enricher is simply DISABLED and lookups return
 * null — alert flow is never blocked by geo problems.
 *
 * The reader factory is injectable so tests can verify the mapping
 * without shipping a real .mmdb.
 */
'use strict';

const fs = require('fs');

const DISABLED = {
  enabled: false,
  lookup: async () => null,
};

/**
 * Create a geo-IP enricher.
 *
 * @param {object} opts
 * @param {string} [opts.mmdbPath]  Path to a GeoLite2-City .mmdb file
 * @param {Function} [opts.readerFactory]  () => reader with .get(ip)
 * @returns {Promise<{enabled: boolean, lookup: (ip: string) => Promise<object|null>}>}
 */
async function createGeoIPEnricher({ mmdbPath = '', readerFactory = null } = {}) {
  if (!mmdbPath) return { ...DISABLED };

  let reader;
  try {
    await fs.promises.access(mmdbPath, fs.constants.R_OK);
    reader = readerFactory
      ? readerFactory(mmdbPath)
      : new (require('mmdb-lib').Reader)(mmdbPath);
  } catch (err) {
    console.warn(
      `[geoip] GeoLite2 database unavailable (${mmdbPath}): ${err.message} — geo enrichment disabled`
    );
    return { ...DISABLED };
  }

  const lookup = async (ip) => {
    if (!ip) return null;
    try {
      const rec = await reader.get(ip);
      if (!rec) return null;

      const country =
        (rec.country &&
          (rec.country.iso_code ||
            (rec.country.names && rec.country.names.en))) ||
        null;
      const city =
        (rec.city && rec.city.names && rec.city.names.en) || null;
      const lat = rec.location ? rec.location.latitude : null;
      const lon = rec.location ? rec.location.longitude : null;
      const asn = rec.asn || null;

      if (!country && !city && lat === null) return null;
      return { country, city, lat, lon, asn };
    } catch (err) {
      // Per-IP lookup failures (e.g. unsupported family) are non-fatal.
      return null;
    }
  };

  return { enabled: true, lookup };
}

module.exports = { createGeoIPEnricher };
