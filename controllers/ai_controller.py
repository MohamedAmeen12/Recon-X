"""
AI Controller - API Endpoints for ReconX AI Assistant
"""

from flask import Blueprint, request, jsonify, session
from bson.objectid import ObjectId
import config.database as db_config
from middlewares.auth_middleware import login_required
from utils.ai_security_assistant import (
    generate_summary,
    calculate_security_score,
    generate_fix_priorities,
    answer_custom_question
)
from controllers.report_controller import enrich_report_data

ai_bp = Blueprint('ai', __name__)

def get_scan_results(report_id):
    """
    Helper to fetch and enrich scan results.
    """
    try:
        print(f"[AI Debug] get_scan_results called with ID: {report_id}")
        if db_config.reports_collection is None:
            print("[AI Debug] reports_collection is None!")
            return None
            
        try:
            oid = ObjectId(report_id)
        except Exception as e:
            print(f"[AI Debug] Invalid ObjectId format: {report_id} - {e}")
            return None

        record = db_config.reports_collection.find_one({"_id": oid})
        if not record:
            print(f"[AI Debug] No record found in DB for ID: {report_id}")
            return None
        
        print(f"[AI Debug] Record found for domain: {record.get('domain')}. Proceeding to enrichment.")
        # Enrich just like the report generator and dashboard
        record = enrich_report_data(record)
        
        res = record.get("result")
        if res is None:
            print("[AI Debug] record['result'] is None after enrichment!")
            return {} # Return empty dict instead of None to distinguish from "not found"
        
        print(f"[AI Debug] Retrieval successful. result keys: {list(res.keys())}")
        return res
    except Exception as e:
        print(f"[AI Controller] Error fetching scan: {e}")
        import traceback
        traceback.print_exc()
        return None

@ai_bp.route("/api/ai/summarize", methods=["POST"])
@login_required
def ai_summarize():
    data = request.get_json() or {}
    report_id = data.get("report_id")
    
    if not report_id:
        return jsonify({"error": "Report ID is required"}), 400
    
    scan_results = get_scan_results(report_id)
    if scan_results is None:
        return jsonify({"error": "Scan results not found"}), 404
    
    response = generate_summary(scan_results)
    return jsonify({"answer": response})

@ai_bp.route("/api/ai/score", methods=["POST"])
@login_required
def ai_score():
    data = request.get_json() or {}
    report_id = data.get("report_id")
    
    if not report_id:
        return jsonify({"error": "Report ID is required"}), 400
    
    scan_results = get_scan_results(report_id)
    if scan_results is None:
        return jsonify({"error": "Scan results not found"}), 404
    
    response = calculate_security_score(scan_results)
    return jsonify({"answer": response})

@ai_bp.route("/api/ai/prioritize", methods=["POST"])
@login_required
def ai_prioritize():
    data = request.get_json() or {}
    report_id = data.get("report_id")
    
    if not report_id:
        return jsonify({"error": "Report ID is required"}), 400
    
    scan_results = get_scan_results(report_id)
    if scan_results is None:
        return jsonify({"error": "Scan results not found"}), 404
    
    response = generate_fix_priorities(scan_results)
    return jsonify({"answer": response})

@ai_bp.route("/api/ai/biggest_risk", methods=["POST"])
@login_required
def ai_biggest_risk():
    data = request.get_json() or {}
    report_id = data.get("report_id")
    
    if not report_id:
        return jsonify({"error": "Report ID is required"}), 400
    
    scan_results = get_scan_results(report_id)
    if scan_results is None:
        return jsonify({"error": "Scan results not found"}), 404
    
    from utils.ai_security_assistant import explain_biggest_risk
    response = explain_biggest_risk(scan_results)
    return jsonify({"answer": response})

@ai_bp.route("/api/ai/ask", methods=["POST"])
@login_required
def ai_ask():
    data = request.get_json() or {}
    report_id = data.get("report_id")
    question = data.get("question")
    
    if not report_id or not question:
        return jsonify({"error": "Report ID and question are required"}), 400
    
    scan_results = get_scan_results(report_id)
    if scan_results is None:
        return jsonify({"error": "Scan results not found"}), 404
    
    response = answer_custom_question(scan_results, question)
    return jsonify({"answer": response})
