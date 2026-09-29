# ==========================================
# SPYGUARD
# AI-POWERED SPYWARE DETECTION &
# THREAT ANALYSIS SYSTEM
#
# Defensive / Simulated Security Project
# ==========================================


from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session
)

from config import get_db_connection

from detector.behavior_analyzer import analyze_behavior

# AI / ML classifier
from detector.ml_classifier import predict_threat

from werkzeug.security import check_password_hash


# ==========================================
# FLASK APPLICATION
# ==========================================

app = Flask(__name__)

app.secret_key = "spyguard-development-secret-key"


# ==========================================
# GLOBAL TEMPLATE USER INFORMATION
# ==========================================

@app.context_processor
def inject_user_info():

    return {
        "username": session.get(
            "username",
            "User"
        ),

        "role": session.get(
            "role",
            "user"
        )
    }


# ==========================================
# LOGIN REQUIRED
# ==========================================

def login_required():

    if "user_id" not in session:

        return False

    return True


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# ==========================================
# LOGIN
# ==========================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )


        # --------------------------------------
        # Basic validation
        # --------------------------------------

        if not username or not password:

            return render_template(
                "login.html",
                error=(
                    "Please enter username "
                    "and password."
                )
            )


        # --------------------------------------
        # Database connection
        # --------------------------------------

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )


        query = """

            SELECT
                id,
                username,
                email,
                password_hash,
                role

            FROM users

            WHERE username = %s

        """


        cursor.execute(
            query,
            (username,)
        )


        user = cursor.fetchone()


        cursor.close()

        connection.close()


        # --------------------------------------
        # Check credentials
        # --------------------------------------

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session["user_id"] = user["id"]

            session["username"] = (
                user["username"]
            )

            session["role"] = (
                user["role"]
            )


            return redirect(
                url_for("dashboard")
            )


        return render_template(
            "login.html",
            error=(
                "Invalid username "
                "or password."
            )
        )


    return render_template(
        "login.html"
    )


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    if not login_required():

        return redirect(
            url_for("login")
        )


    connection = get_db_connection()

    cursor = connection.cursor(
        dictionary=True
    )


    # --------------------------------------
    # Total Threats
    # --------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM threats
    """)

    threat_result = cursor.fetchone()

    total_threats = (
        threat_result["total"]
    )


    # --------------------------------------
    # Active Threats
    # --------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM threats
        WHERE severity IN
        ('high', 'critical')
    """)

    active_result = cursor.fetchone()

    active_threats = (
        active_result["total"]
    )


    # --------------------------------------
    # Total Scans
    # --------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM scan_results
    """)

    scan_result = cursor.fetchone()

    total_scans = (
        scan_result["total"]
    )


    # --------------------------------------
    # Latest Threat
    # --------------------------------------

    cursor.execute("""
        SELECT
            threat_name,
            threat_type,
            severity,
            risk_score,
            detected_at

        FROM threats

        ORDER BY detected_at DESC

        LIMIT 1
    """)

    latest_threat = (
        cursor.fetchone()
    )


    # --------------------------------------
    # Recent Activity
    # --------------------------------------

    cursor.execute("""
        SELECT
            event_type,
            process_name,
            risk_score,
            status,
            detected_at

        FROM activity_logs

        ORDER BY detected_at DESC

        LIMIT 5
    """)

    recent_activity = (
        cursor.fetchall()
    )


    cursor.close()

    connection.close()


    return render_template(
        "dashboard.html",

        total_threats=total_threats,

        active_threats=active_threats,

        total_scans=total_scans,

        latest_threat=latest_threat,

        recent_activity=recent_activity
    )


# ==========================================
# THREAT SCANNER PAGE
# ==========================================

@app.route("/scanner")
def scanner():

    if not login_required():

        return redirect(
            url_for("login")
        )


    return render_template(
        "scanner.html"
    )


# ==========================================
# RUN DYNAMIC SIMULATED SCAN
#
# Rule-Based Analyzer
# +
# AI / ML Classifier
# ==========================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    if not login_required():

        return redirect(
            url_for("login")
        )


    # ======================================
    # GET SELECTED SIMULATED BEHAVIORS
    # ======================================

    selected_behaviors = (
        request.form.getlist(
            "behaviors"
        )
    )


    # ======================================
    # VALIDATE SELECTION
    # ======================================

    if not selected_behaviors:

        return render_template(
            "scanner.html",
            error=(
                "Please select at least "
                "one simulated behavior."
            )
        )


    # ======================================
    # COMBINE SELECTED BEHAVIORS
    # ======================================

    behavior_text = " ".join(
        selected_behaviors
    )


    # ======================================
    # RULE-BASED ANALYSIS
    # ======================================

    analysis = analyze_behavior(
        behavior_text
    )


    risk_score = analysis[
        "risk_score"
    ]

    threat_level = analysis[
        "threat_level"
    ]

    explanation = analysis[
        "explanation"
    ]

    recommendation = analysis[
        "recommendation"
    ]

    detected_indicators = analysis[
        "detected_indicators"
    ]

    indicator_count = analysis[
        "indicator_count"
    ]


    # ======================================
    # AI / ML ANALYSIS
    # ======================================

    ml_result = predict_threat(
        behavior_text
    )


    ml_threat_level = ml_result[
        "threat_level"
    ]

    ml_confidence = ml_result[
        "confidence"
    ]


    # ======================================
    # SCAN INFORMATION
    # ======================================

    scan_type = (
        "AI/ML Spyware Behavior Simulation"
    )

    target = (
        "Local Test Environment"
    )

    result = threat_level


    # ======================================
    # BUILD SCAN DETAILS
    # ======================================

    details = (

        f"SpyGuard analyzed "
        f"{indicator_count} simulated "
        f"behavior indicator(s). "

        f"Rule-based threat level: "
        f"{threat_level}. "

        f"Risk score: "
        f"{risk_score}/100. "

        f"AI/ML prediction: "
        f"{ml_threat_level}. "

        f"AI/ML confidence: "
        f"{ml_confidence}%. "

        f"Detected behaviors: "
        f"{', '.join(selected_behaviors)}. "

        f"{explanation} "

        f"Recommendation: "
        f"{recommendation}"

    )


    # ======================================
    # DATABASE CONNECTION
    # ======================================

    connection = get_db_connection()

    cursor = connection.cursor()


    # ======================================
    # SAVE SCAN RESULT
    # ======================================

    insert_scan = """

        INSERT INTO scan_results
        (
            scan_type,
            target,
            result,
            risk_score,
            details
        )

        VALUES
        (
            %s,
            %s,
            %s,
            %s,
            %s
        )

    """


    scan_values = (

        scan_type,

        target,

        result,

        risk_score,

        details

    )


    cursor.execute(
        insert_scan,
        scan_values
    )


    # ======================================
    # MAP THREAT LEVEL TO DATABASE STATUS
    # ======================================

    if threat_level == "Critical":

        status = "critical"

    elif threat_level == "High Risk":

        status = "high_risk"

    elif threat_level == "Suspicious":

        status = "suspicious"

    else:

        status = "safe"


    # ======================================
    # SAVE ACTIVITY LOG
    # ======================================

    log_description = (

        explanation

        + " "

        + "AI/ML Prediction: "

        + ml_threat_level

        + ". "

        + "AI/ML Confidence: "

        + str(ml_confidence)

        + "%. "

        + "Recommendation: "

        + recommendation

    )


    insert_log = """

        INSERT INTO activity_logs
        (
            event_type,
            process_name,
            description,
            source_ip,
            risk_score,
            status
        )

        VALUES
        (
            %s,
            %s,
            %s,
            %s,
            %s,
            %s
        )

    """


    log_values = (

        "Threat Scanner",

        "SpyGuard AI/ML Scanner",

        log_description,

        "127.0.0.1",

        risk_score,

        status

    )


    cursor.execute(
        insert_log,
        log_values
    )


    # ======================================
    # CREATE THREAT
    #
    # Only for higher-risk simulations
    # ======================================

    threat_id = None


    if risk_score >= 60:


        # ----------------------------------
        # Determine severity
        # ----------------------------------

        if threat_level == "Critical":

            severity = "critical"

        elif threat_level == "High Risk":

            severity = "high"

        else:

            severity = "medium"


        # ----------------------------------
        # Threat name
        # ----------------------------------

        threat_name = (
            "Suspicious Spyware-Like Behavior"
        )


        threat_type = (
            "AI/ML Behavioral Detection"
        )


        # ----------------------------------
        # Threat description
        # ----------------------------------

        threat_description = (

            f"SpyGuard detected "
            f"{indicator_count} "
            f"suspicious simulated "
            f"behavior indicator(s). "

            + explanation

            + " "

            + f"AI/ML prediction: "
            f"{ml_threat_level}. "

            + f"AI/ML confidence: "
            f"{ml_confidence}%."

        )


        # ----------------------------------
        # INSERT THREAT
        # ----------------------------------

        insert_threat = """

            INSERT INTO threats
            (
                threat_name,
                threat_type,
                description,
                severity,
                risk_score,
                recommendation
            )

            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )

        """


        threat_values = (

            threat_name,

            threat_type,

            threat_description,

            severity,

            risk_score,

            recommendation

        )


        cursor.execute(
            insert_threat,
            threat_values
        )


        threat_id = cursor.lastrowid


        # ----------------------------------
        # CREATE ALERT
        # ----------------------------------

        alert_message = (

            f"{threat_level} threat detected. "

            f"Risk score: "
            f"{risk_score}/100. "

            f"Detected indicators: "
            f"{indicator_count}. "

            f"AI/ML prediction: "
            f"{ml_threat_level}. "

            f"AI/ML confidence: "
            f"{ml_confidence}%."

        )


        insert_alert = """

            INSERT INTO alerts
            (
                threat_id,
                alert_message,
                severity,
                is_read
            )

            VALUES
            (
                %s,
                %s,
                %s,
                %s
            )

        """


        alert_values = (

            threat_id,

            alert_message,

            severity,

            False

        )


        cursor.execute(
            insert_alert,
            alert_values
        )


    # ======================================
    # COMMIT DATABASE CHANGES
    # ======================================

    connection.commit()


    cursor.close()

    connection.close()


    # ======================================
    # SHOW SCAN RESULT
    # ======================================

    return render_template(

        "scan_result.html",

        scan_type=scan_type,

        target=target,

        result=result,

        risk_score=risk_score,

        details=details,

        threat_level=threat_level,

        explanation=explanation,

        recommendation=recommendation,

        detected_indicators=(
            detected_indicators
        ),

        indicator_count=(
            indicator_count
        ),

        selected_behaviors=(
            selected_behaviors
        ),

        ml_threat_level=(
            ml_threat_level
        ),

        ml_confidence=(
            ml_confidence
        )

    )


# ==========================================
# BEHAVIOR ANALYSIS PAGE
# ==========================================

@app.route("/behavior")
def behavior():

    if not login_required():

        return redirect(
            url_for("login")
        )


    return render_template(
        "behavior.html"
    )


# ==========================================
# ANALYZE MULTIPLE BEHAVIORS
#
# Rule-Based Analyzer
# +
# AI / ML Classifier
# ==========================================

@app.route(
    "/behavior/analyze",
    methods=["POST"]
)
def analyze_behavior_route():

    if not login_required():

        return redirect(
            url_for("login")
        )


    # ======================================
    # GET SELECTED BEHAVIORS
    # ======================================

    selected_behaviors = (
        request.form.getlist(
            "behaviors"
        )
    )


    # ======================================
    # VALIDATE SELECTION
    # ======================================

    if not selected_behaviors:

        return render_template(
            "behavior.html",
            error=(
                "Please select at least "
                "one simulated behavior."
            )
        )


    # ======================================
    # COMBINE BEHAVIORS
    # ======================================

    behavior_text = " ".join(
        selected_behaviors
    )


    # ======================================
    # RULE-BASED ANALYSIS
    # ======================================

    analysis = analyze_behavior(
        behavior_text
    )


    risk_score = analysis[
        "risk_score"
    ]

    threat_level = analysis[
        "threat_level"
    ]

    explanation = analysis[
        "explanation"
    ]

    recommendation = analysis[
        "recommendation"
    ]

    detected_indicators = analysis[
        "detected_indicators"
    ]

    indicator_count = analysis[
        "indicator_count"
    ]


    # ======================================
    # AI / ML THREAT PREDICTION
    # ======================================

    ml_result = predict_threat(
        behavior_text
    )


    ml_threat_level = ml_result[
        "threat_level"
    ]

    ml_confidence = ml_result[
        "confidence"
    ]


    # ======================================
    # DATABASE CONNECTION
    # ======================================

    connection = get_db_connection()

    cursor = connection.cursor()


    # ======================================
    # MAP THREAT LEVEL TO DATABASE STATUS
    # ======================================

    if threat_level == "Critical":

        status = "critical"

    elif threat_level == "High Risk":

        status = "high_risk"

    elif threat_level == "Suspicious":

        status = "suspicious"

    else:

        status = "safe"


    # ======================================
    # STORE ACTIVITY LOG
    # ======================================

    log_description = (

        explanation

        + " "

        + "Recommendation: "

        + recommendation

        + " "

        + "AI/ML Prediction: "

        + ml_threat_level

        + ". "

        + "AI/ML Confidence: "

        + str(ml_confidence)

        + "%."

    )


    insert_log = """

        INSERT INTO activity_logs
        (
            event_type,
            process_name,
            description,
            source_ip,
            risk_score,
            status
        )

        VALUES
        (
            %s,
            %s,
            %s,
            %s,
            %s,
            %s
        )

    """


    log_values = (

        "Behavior Analysis",

        "SpyGuard AI/ML Simulation",

        log_description,

        "127.0.0.1",

        risk_score,

        status

    )


    cursor.execute(
        insert_log,
        log_values
    )


    # ======================================
    # CREATE THREAT AND ALERT
    # ======================================

    threat_id = None


    if risk_score >= 60:


        # ----------------------------------
        # Determine severity
        # ----------------------------------

        if threat_level == "Critical":

            severity = "critical"

        elif threat_level == "High Risk":

            severity = "high"

        else:

            severity = "medium"


        # ----------------------------------
        # Threat name
        # ----------------------------------

        threat_name = (
            "Suspicious Spyware-Like Behavior"
        )


        threat_type = (
            "AI/ML Behavioral Detection"
        )


        # ----------------------------------
        # Threat description
        # ----------------------------------

        threat_description = (

            f"SpyGuard detected "
            f"{indicator_count} "
            f"suspicious simulated "
            f"behavior indicator(s). "

            + explanation

            + " "

            + f"AI/ML prediction: "
            f"{ml_threat_level}. "

            + f"AI/ML confidence: "
            f"{ml_confidence}%."

        )


        # ----------------------------------
        # INSERT THREAT
        # ----------------------------------

        insert_threat = """

            INSERT INTO threats
            (
                threat_name,
                threat_type,
                description,
                severity,
                risk_score,
                recommendation
            )

            VALUES
            (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )

        """


        threat_values = (

            threat_name,

            threat_type,

            threat_description,

            severity,

            risk_score,

            recommendation

        )


        cursor.execute(
            insert_threat,
            threat_values
        )


        threat_id = cursor.lastrowid


        # ----------------------------------
        # CREATE ALERT
        # ----------------------------------

        alert_message = (

            f"{threat_level} threat detected. "

            f"Risk score: "
            f"{risk_score}/100. "

            f"Detected indicators: "
            f"{indicator_count}. "

            f"AI/ML prediction: "
            f"{ml_threat_level}. "

            f"AI/ML confidence: "
            f"{ml_confidence}%."

        )


        insert_alert = """

            INSERT INTO alerts
            (
                threat_id,
                alert_message,
                severity,
                is_read
            )

            VALUES
            (
                %s,
                %s,
                %s,
                %s
            )

        """


        alert_values = (

            threat_id,

            alert_message,

            severity,

            False

        )


        cursor.execute(
            insert_alert,
            alert_values
        )


    # ======================================
    # COMMIT DATABASE CHANGES
    # ======================================

    connection.commit()


    cursor.close()

    connection.close()


    # ======================================
    # SHOW ANALYSIS RESULT
    # ======================================

    return render_template(

        "behavior_result.html",

        # Rule-based analysis

        risk_score=risk_score,

        threat_level=threat_level,

        explanation=explanation,

        recommendation=recommendation,

        detected_indicators=(
            detected_indicators
        ),

        indicator_count=(
            indicator_count
        ),

        selected_behaviors=(
            selected_behaviors
        ),

        # AI / ML analysis

        ml_threat_level=(
            ml_threat_level
        ),

        ml_confidence=(
            ml_confidence
        )

    )


# ==========================================
# THREAT ALERTS
# ==========================================

@app.route("/alerts")
def alerts():

    if not login_required():

        return redirect(
            url_for("login")
        )


    connection = get_db_connection()

    cursor = connection.cursor(
        dictionary=True
    )


    query = """

        SELECT
            id,
            threat_id,
            alert_message,
            severity,
            is_read,
            created_at

        FROM alerts

        ORDER BY created_at DESC

    """


    cursor.execute(query)

    alerts_data = cursor.fetchall()


    cursor.close()

    connection.close()


    return render_template(
        "alerts.html",
        alerts=alerts_data
    )


# ==========================================
# SECURITY LOGS
# ==========================================

@app.route("/logs")
def logs():

    if not login_required():

        return redirect(
            url_for("login")
        )


    connection = get_db_connection()

    cursor = connection.cursor(
        dictionary=True
    )


    query = """

        SELECT
            id,
            event_type,
            process_name,
            description,
            source_ip,
            risk_score,
            status,
            detected_at

        FROM activity_logs

        ORDER BY detected_at DESC

    """


    cursor.execute(query)

    logs_data = cursor.fetchall()


    cursor.close()

    connection.close()


    return render_template(
        "logs.html",
        logs=logs_data
    )


# ==========================================
# REPORTS
# ==========================================

@app.route("/reports")
def reports():

    if not login_required():

        return redirect(
            url_for("login")
        )


    connection = get_db_connection()

    cursor = connection.cursor(
        dictionary=True
    )


    # --------------------------------------
    # Total Scans
    # --------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM scan_results
    """)

    total_scans = cursor.fetchone()[
        "total"
    ]


    # --------------------------------------
    # Total Threats
    # --------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM threats
    """)

    total_threats = cursor.fetchone()[
        "total"
    ]


    # --------------------------------------
    # Activity Logs
    # --------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM activity_logs
    """)

    total_logs = cursor.fetchone()[
        "total"
    ]


    # --------------------------------------
    # Suspicious Events
    # --------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM activity_logs

        WHERE status IN
        (
            'suspicious',
            'high_risk',
            'critical'
        )

    """)

    suspicious_events = (
        cursor.fetchone()["total"]
    )


    # --------------------------------------
    # Status Breakdown
    # --------------------------------------

    cursor.execute("""
        SELECT
            status,
            COUNT(*) AS total

        FROM activity_logs

        GROUP BY status

    """)


    status_rows = cursor.fetchall()


    status_counts = {

        "safe": 0,

        "suspicious": 0,

        "high_risk": 0,

        "critical": 0

    }


    for row in status_rows:

        if row["status"] in status_counts:

            status_counts[
                row["status"]
            ] = row["total"]


    # --------------------------------------
    # Latest Scan
    # --------------------------------------

    cursor.execute("""
        SELECT
            scan_type,
            target,
            result,
            risk_score,
            details,
            scanned_at

        FROM scan_results

        ORDER BY scanned_at DESC

        LIMIT 1

    """)


    latest_scan = cursor.fetchone()


    # --------------------------------------
    # Latest Threat
    # --------------------------------------

    cursor.execute("""
        SELECT
            threat_name,
            threat_type,
            severity,
            risk_score,
            recommendation,
            detected_at

        FROM threats

        ORDER BY detected_at DESC

        LIMIT 1

    """)


    latest_threat = cursor.fetchone()


    cursor.close()

    connection.close()


    return render_template(

        "reports.html",

        total_scans=total_scans,

        total_threats=total_threats,

        total_logs=total_logs,

        suspicious_events=(
            suspicious_events
        ),

        status_counts=status_counts,

        latest_scan=latest_scan,

        latest_threat=latest_threat

    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(

        debug=True,

        host="127.0.0.1",

        port=5000

    )