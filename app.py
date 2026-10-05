from flask import Flask, render_template, request

from core.email_parser import parse_eml
from core.authentication import analyze_authentication
from core.routing import analyze_routing
from core.infrastructure import analyze_ips, create_map_data
from core.correlation import correlate_evidence
from core.scoring import calculate_threat_score
from core.ai_engine import classify_email


app = Flask(__name__)


# ============================================================
# EMAIL ANALYSIS PIPELINE
# ============================================================

def analyze_email(file_bytes):

    # --------------------------------------------------------
    # 1. PARSE EMAIL
    # --------------------------------------------------------

    email_data = parse_eml(file_bytes)


    # --------------------------------------------------------
    # 2. AUTHENTICATION ANALYSIS
    # --------------------------------------------------------

    authentication = analyze_authentication(
        email_data.get(
            "authentication_results",
            ""
        )
    )


    # --------------------------------------------------------
    # 3. ROUTING ANALYSIS
    # --------------------------------------------------------

    routing = analyze_routing(
        email_data.get(
            "received_headers",
            []
        )
    )


    # --------------------------------------------------------
    # 4. IP / INFRASTRUCTURE ANALYSIS
    # --------------------------------------------------------

    ip_locations = analyze_ips(
        email_data.get(
            "ips",
            []
        ),
        email_data.get(
            "received_headers",
            []
        )
    )

    map_data = create_map_data(
        ip_locations
    )


    # --------------------------------------------------------
    # 5. EVIDENCE CORRELATION
    # --------------------------------------------------------

    correlation = correlate_evidence(
        authentication,
        email_data.get(
            "sender",
            ""
        ),
        email_data.get(
            "reply_to",
            ""
        ),
        email_data.get(
            "return_path",
            ""
        ),
        email_data.get(
            "urls",
            []
        ),
        email_data.get(
            "domains",
            []
        ),
        email_data.get(
            "body_text",
            "")
    )


    # --------------------------------------------------------
    # 6. THREAT SCORING
    # --------------------------------------------------------

    scoring = calculate_threat_score(
        email_data=email_data,
        authentication=authentication,
        correlation_result=correlation,
        ip_locations=ip_locations
    )


    # --------------------------------------------------------
    # 7. AI THREAT CLASSIFICATION
    # --------------------------------------------------------

    ai_email_data = dict(
        email_data
    )

    # The AI engine expects authentication
    # information as a dictionary.
    ai_email_data[
        "authentication_results"
    ] = authentication


    ai_result = classify_email(
        email_data=ai_email_data,
        correlation_result=correlation
    )


    # --------------------------------------------------------
    # 8. FIND POSSIBLE SENDER / RELAY IPS
    # --------------------------------------------------------

    sender_candidates = []

    for item in ip_locations:

        if item.get(
            "role"
        ) == "Possible Sender / Relay Network":

            sender_candidates.append(
                item
            )


    # --------------------------------------------------------
    # 9. BUILD FINAL RESULT
    # --------------------------------------------------------

    result = {

        # ====================================================
        # EMAIL IDENTITY
        # ====================================================

        "sender":
            email_data.get(
                "sender",
                ""
            ),

        "from_address":
            email_data.get(
                "sender",
                ""
            ),

        "to":
            email_data.get(
                "to",
                ""
            ),

        "cc":
            email_data.get(
                "cc",
                ""
            ),

        "reply_to":
            email_data.get(
                "reply_to",
                ""
            ),

        "return_path":
            email_data.get(
                "return_path",
                ""
            ),

        "subject":
            email_data.get(
                "subject",
                ""
            ),

        "date":
            email_data.get(
                "date",
                ""
            ),

        "message_id":
            email_data.get(
                "message_id",
                ""
            ),


        # ====================================================
        # AUTHENTICATION
        # ====================================================

        "spf":
            authentication.get(
                "spf",
                "unknown"
            ).upper(),

        "dkim":
            authentication.get(
                "dkim",
                "unknown"
            ).upper(),

        "dmarc":
            authentication.get(
                "dmarc",
                "unknown"
            ).upper(),

        "authentication":
            authentication,


        # ====================================================
        # ROUTING
        # ====================================================

        "routing":
            routing,

        "routing_chain":
            routing.get(
                "routing_chain",
                []
            ),

        "received_headers":
            email_data.get(
                "received_headers",
                []
            ),


        # ====================================================
        # INFRASTRUCTURE
        # ====================================================

        "ips":
            email_data.get(
                "ips",
                []
            ),

        "ip_locations":
            ip_locations,

        "map_data":
            map_data,

        "sender_candidates":
            sender_candidates,


        # ====================================================
        # INDICATORS
        # ====================================================

        "urls":
            email_data.get(
                "urls",
                []
            ),

        "domains":
            email_data.get(
                "domains",
                []
            ),

        "attachments":
            email_data.get(
                "attachments",
                []
            ),


        # ====================================================
        # RAW EMAIL DATA
        # ====================================================

        "headers":
            email_data.get(
                "headers",
                []
            ),

        "body_text":
            email_data.get(
                "body_text",
                ""
            ),


        # ====================================================
        # CORRELATION ENGINE
        # ====================================================

        "correlation":
            correlation,

        "evidence":
            correlation.get(
                "evidence",
                []
            ),

        "correlations":
            correlation.get(
                "correlations",
                []
            ),

        "overall_confidence":
            correlation.get(
                "overall_confidence",
                0
            ),


        # ====================================================
        # THREAT SCORE
        # ====================================================

        "score":
            scoring.get(
                "score",
                0
            ),

        "severity":
            scoring.get(
                "severity",
                "LOW"
            ),

        "reasons":
            scoring.get(
                "reasons",
                []
            ),

        "score_breakdown":
            scoring.get(
                "breakdown",
                {}
            ),

        "signal_count":
            scoring.get(
                "signal_count",
                0
            ),


        # ====================================================
        # AI CLASSIFICATION
        # ====================================================

        "ai_category":
            ai_result.get(
                "category",
                "Unknown"
            ),

        "ai_confidence":
            ai_result.get(
                "confidence",
                0
            ),

        "ai_explanation":
            ai_result.get(
                "explanation",
                ""
            ),

        "ai_indicators":
            ai_result.get(
                "indicators",
                []
            ),


        # ----------------------------------------------------
        # RAW AI SCORES
        # ----------------------------------------------------

        "ai_class_scores":
            ai_result.get(
                "raw_scores",
                ai_result.get(
                    "class_scores",
                    {}
                )
            ),


        # ----------------------------------------------------
        # NEW: NORMALIZED AI SCORES
        # ----------------------------------------------------

        "ai_normalized_scores":
            ai_result.get(
                "normalized_scores",
                {}
            ),


        # ----------------------------------------------------
        # AI EVIDENCE INFORMATION
        # ----------------------------------------------------

        "ai_evidence_groups":
            ai_result.get(
                "evidence_groups",
                0
            ),

        "ai_correlation_signals":
            ai_result.get(
                "correlation_signals",
                []
            ),

        "ai_indicator_count":
            ai_result.get(
                "indicator_count",
                0
            )
    }


    return result


# ============================================================
# MAIN ROUTE
# ============================================================

@app.route(
    "/",
    methods=[
        "GET",
        "POST"
    ]
)
def index():

    result = None


    # --------------------------------------------------------
    # GET / POST
    # --------------------------------------------------------

    if request.method == "POST":

        uploaded_file = request.files.get(
            "email_file"
        )


        # ----------------------------------------------------
        # NO FILE
        # ----------------------------------------------------

        if not uploaded_file:

            result = {
                "error":
                    "No email file was uploaded."
            }


        else:

            filename = (
                uploaded_file.filename
                or ""
            )


            # ------------------------------------------------
            # FILE TYPE VALIDATION
            # ------------------------------------------------

            if not filename.lower().endswith(
                ".eml"
            ):

                result = {
                    "error":
                        "Please upload a valid .eml file."
                }


            else:

                try:

                    # ----------------------------------------
                    # READ FILE
                    # ----------------------------------------

                    file_bytes = (
                        uploaded_file.read()
                    )


                    if not file_bytes:

                        raise ValueError(
                            "The uploaded file is empty."
                        )


                    # ----------------------------------------
                    # ANALYZE EMAIL
                    # ----------------------------------------

                    result = analyze_email(
                        file_bytes
                    )


                except Exception as error:

                    print(
                        "TraceMail analysis error:",
                        error
                    )

                    result = {
                        "error":
                            str(error)
                    }


    # --------------------------------------------------------
    # RENDER DASHBOARD
    # --------------------------------------------------------

    return render_template(
        "index.html",
        result=result
    )


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )