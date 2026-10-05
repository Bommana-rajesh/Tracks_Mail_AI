/* =========================================================
   TraceMail AI - Map Module
   Handles IP infrastructure / routing map
   ========================================================= */

document.addEventListener("DOMContentLoaded", function () {

    const mapContainer = document.getElementById("threat-map");

    // No map on initial page / error page
    if (!mapContainer) {
        return;
    }

    // Leaflet not loaded
    if (typeof L === "undefined") {
        console.error("Leaflet library is not loaded.");
        return;
    }

    // ---------------------------------------------------------
    // Read IP location data injected by Flask
    // ---------------------------------------------------------

    const dataElement = document.getElementById("ip-location-data");

    let ipLocations = [];

    if (dataElement) {
        try {
            ipLocations = JSON.parse(
                dataElement.textContent || "[]"
            );
        } catch (error) {
            console.error(
                "Failed to parse IP location data:",
                error
            );
            ipLocations = [];
        }
    }

    // ---------------------------------------------------------
    // Create map
    // ---------------------------------------------------------

    const map = L.map("threat-map", {
        zoomControl: true,
        scrollWheelZoom: true
    }).setView([20, 78], 3);

    // ---------------------------------------------------------
    // OpenStreetMap tiles
    // ---------------------------------------------------------

    L.tileLayer(
        "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
        {
            maxZoom: 19,
            attribution:
                '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank">OpenStreetMap</a>'
        }
    ).addTo(map);

    // ---------------------------------------------------------
    // No IP locations
    // ---------------------------------------------------------

    if (!Array.isArray(ipLocations) || ipLocations.length === 0) {

        const emptyMessage = L.control({
            position: "topright"
        });

        emptyMessage.onAdd = function () {

            const div = L.DomUtil.create(
                "div",
                "map-empty-message"
            );

            div.innerHTML =
                "<strong>No geolocatable infrastructure</strong><br>" +
                "<span>No public IP location data available.</span>";

            return div;
        };

        emptyMessage.addTo(map);

        return;
    }

    // ---------------------------------------------------------
    // Store valid coordinates
    // ---------------------------------------------------------

    const points = [];

    // ---------------------------------------------------------
    // Create markers
    // ---------------------------------------------------------

    ipLocations.forEach(function (item, index) {

        if (!item) {
            return;
        }

        const latitude = Number(
            item.latitude ?? item.lat
        );

        const longitude = Number(
            item.longitude ?? item.lon ?? item.long
        );

        // Invalid coordinates
        if (
            !Number.isFinite(latitude) ||
            !Number.isFinite(longitude)
        ) {
            return;
        }

        // Coordinates outside valid geographic range
        if (
            latitude < -90 ||
            latitude > 90 ||
            longitude < -180 ||
            longitude > 180
        ) {
            return;
        }

        points.push([latitude, longitude]);

        // -----------------------------------------------------
        // Extract metadata
        // -----------------------------------------------------

        const ip =
            item.ip ||
            "Unknown IP";

        const provider =
            item.provider ||
            item.org ||
            item.organization ||
            "Unknown provider";

        const country =
            item.country ||
            item.country_name ||
            "Unknown";

        const region =
            item.region ||
            item.region_name ||
            "";

        const city =
            item.city ||
            "";

        const asn =
            item.asn ||
            "Unknown";

        const hostname =
            item.hostname ||
            "Unavailable";

        const role =
            item.role ||
            item.ip_role ||
            "Infrastructure / Relay";

        const locationConfidence =
            item.location_confidence ||
            "Unknown";

        const roleConfidence =
            item.role_confidence ||
            "Unknown";

        // -----------------------------------------------------
        // Popup
        // -----------------------------------------------------

        const popupHTML = `
            <div class="map-popup">

                <div class="map-popup-title">
                    TRACE NODE #${index + 1}
                </div>

                <div class="map-popup-ip">
                    ${escapeHTML(ip)}
                </div>

                <div class="map-popup-row">
                    <strong>Role:</strong>
                    ${escapeHTML(role)}
                </div>

                <div class="map-popup-row">
                    <strong>Provider:</strong>
                    ${escapeHTML(provider)}
                </div>

                <div class="map-popup-row">
                    <strong>Location:</strong>
                    ${escapeHTML(
                        [city, region, country]
                            .filter(Boolean)
                            .join(", ")
                    )}
                </div>

                <div class="map-popup-row">
                    <strong>ASN:</strong>
                    ${escapeHTML(asn)}
                </div>

                <div class="map-popup-row">
                    <strong>Hostname:</strong>
                    ${escapeHTML(hostname)}
                </div>

                <div class="map-popup-row">
                    <strong>Location Confidence:</strong>
                    ${escapeHTML(locationConfidence)}
                </div>

                <div class="map-popup-row">
                    <strong>Role Confidence:</strong>
                    ${escapeHTML(roleConfidence)}
                </div>

            </div>
        `;

        // -----------------------------------------------------
        // Marker
        // -----------------------------------------------------

        const marker = L.marker([
            latitude,
            longitude
        ]).addTo(map);

        marker.bindPopup(popupHTML);

        // -----------------------------------------------------
        // Marker tooltip
        // -----------------------------------------------------

        marker.bindTooltip(
            `${ip} • ${provider}`,
            {
                direction: "top",
                offset: [0, -10]
            }
        );

    });

    // ---------------------------------------------------------
    // Draw routing line
    // ---------------------------------------------------------

    if (points.length > 1) {

        const routingLine = L.polyline(
            points,
            {
                weight: 2,
                opacity: 0.75,
                dashArray: "7 7"
            }
        ).addTo(map);

        routingLine.bindTooltip(
            "Observed infrastructure / routing path",
            {
                sticky: true
            }
        );
    }

    // ---------------------------------------------------------
    // Fit map to markers
    // ---------------------------------------------------------

    if (points.length === 1) {

        map.setView(
            points[0],
            6
        );

    } else if (points.length > 1) {

        const bounds = L.latLngBounds(points);

        map.fitBounds(
            bounds,
            {
                padding: [40, 40],
                maxZoom: 8
            }
        );
    }

    // ---------------------------------------------------------
    // Resize fix
    // ---------------------------------------------------------

    setTimeout(function () {
        map.invalidateSize();
    }, 300);

    window.addEventListener(
        "resize",
        function () {
            map.invalidateSize();
        }
    );

});


/* =========================================================
   Utility: HTML escaping
   Prevents metadata from being interpreted as HTML
   ========================================================= */

function escapeHTML(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}