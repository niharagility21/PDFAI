import os
import json
import uuid
import tempfile
import threading
import traceback
import zipfile
import shutil
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, jsonify, send_file, flash
import pandas as pd
import numpy as np
import logging

from utils.ocr_client import OCRClient
from utils.tables import extract_tables_from_markdown, process_and_serialize
from utils.analyzers import extract_pdf_metadata
from config import Config

# Initialize loggers
app_logger = logging.getLogger('pdf_analyzer')
forensic_logger = logging.getLogger('forensic_analysis')
error_logger = logging.getLogger('errors')

# Create blueprint
pdf_bp = Blueprint('pdf_analyzer', __name__)

# Global storage for processing results
processing_results = {}

# Persistent job storage directory
PERSISTENT_JOB_DIR = "/root/PDFAI/downloads"
os.makedirs(PERSISTENT_JOB_DIR, exist_ok=True)

def save_job_result(job_id, result):
    """Save job result to persistent storage."""
    try:
        # Save job metadata
        persistent_file = os.path.join(PERSISTENT_JOB_DIR, f"{job_id}_result.json")
        # Create a copy without file paths for JSON serialization
        json_result = result.copy()
        # Remove non-serializable items
        for key in ['file_path', 'temp_dir', 'output_dir', 'text_file', 'metadata_file']:
            if key in json_result:
                del json_result[key]
        
        with open(persistent_file, 'w') as f:
            json.dump(json_result, f, indent=2, default=str)
        
        # Copy files to persistent location if they exist
        temp_dir = result.get('temp_dir')
        if temp_dir and os.path.exists(temp_dir):
            persistent_dir = os.path.join(PERSISTENT_JOB_DIR, job_id)
            if not os.path.exists(persistent_dir):
                shutil.copytree(temp_dir, persistent_dir)
                app_logger.info(f"Copied job files to persistent storage: {persistent_dir}")
        
        app_logger.info(f"Job {job_id} saved to persistent storage")
    except Exception as e:
        app_logger.error(f"Failed to save job {job_id}: {e}")

def load_job_result(job_id):
    """Load job result from persistent storage."""
    try:
        persistent_file = os.path.join(PERSISTENT_JOB_DIR, f"{job_id}_result.json")
        persistent_dir = os.path.join(PERSISTENT_JOB_DIR, job_id)
        
        if os.path.exists(persistent_file) and os.path.exists(persistent_dir):
            with open(persistent_file, 'r') as f:
                result = json.load(f)
            
            # Reconstruct file paths
            result['temp_dir'] = persistent_dir
            result['output_dir'] = os.path.join(persistent_dir, "extracted_tables")
            result['text_file'] = os.path.join(persistent_dir, "extracted_tables", "full_text.txt")
            result['metadata_file'] = os.path.join(persistent_dir, "extracted_tables", "forensic_analysis_report.json")
            
            app_logger.info(f"Loaded job {job_id} from persistent storage")
            return result
    except Exception as e:
        app_logger.error(f"Failed to load job {job_id}: {e}")
    return None

@pdf_bp.route('/')
def index():
    """Main application page."""
    return render_template('index.html')

@pdf_bp.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and start processing."""
    try:
        app_logger.info("Received file upload request")

        if 'file' not in request.files:
            app_logger.warning("No file provided in upload request")
            return jsonify({'success': False, 'error': 'No file provided'})

        file = request.files['file']

        if not file or file.filename == '':
            app_logger.warning("No file selected")
            return jsonify({'success': False, 'error': 'No file selected'})

        if not file.filename.lower().endswith('.pdf'):
            app_logger.warning(f"Invalid file type: {file.filename}")
            return jsonify({'success': False, 'error': 'Only PDF files are supported'})

        # Generate unique job ID
        job_id = str(uuid.uuid4())
        app_logger.info(f"Generated job ID: {job_id}")

        # Save uploaded file
        filename = secure_filename(file.filename)
        temp_dir = tempfile.mkdtemp()
        file_path = os.path.join(temp_dir, filename)
        file.save(file_path)

        app_logger.info(f"File saved to: {file_path} (size: {os.path.getsize(file_path)} bytes)")

        # Store job info
        processing_results[job_id] = {
            'status': 'processing',
            'file_path': file_path,
            'temp_dir': temp_dir,
            'progress': 0,
            'message': 'Starting comprehensive forensic analysis...',
            'filename': filename
        }

        # Start processing in background thread
        thread = threading.Thread(target=process_pdf_background, args=(job_id, file_path, temp_dir))
        thread.daemon = True
        thread.start()

        app_logger.info(f"Background processing started for job: {job_id}")
        return jsonify({'success': True, 'job_id': job_id})

    except Exception as e:
        error_logger.error(f"Upload failed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)})

def process_pdf_background(job_id, file_path, temp_dir):
    """Process PDF in background thread with comprehensive forensic analysis."""
    try:
        app_logger.info(f"Starting background processing for job: {job_id}")

        # Update progress
        processing_results[job_id]['progress'] = 10
        processing_results[job_id]['message'] = 'Initializing comprehensive forensic analysis...'

        # Extract comprehensive metadata for forensic analysis
        forensic_logger.info(f"Starting comprehensive forensic analysis for job {job_id}")
        metadata = extract_pdf_metadata(file_path)

        # Validate metadata
        if metadata is None:
            error_logger.error("Comprehensive analysis returned None")
            metadata = {
                'basic_info': {'Error': 'Forensic analysis failed'},
                'security_info': {'encrypted': False, 'revisions': 0},
                'forensic_indicators': ['Comprehensive analysis failed'],
                'risk_assessment': 'Unknown',
                'recommendations': ['Unable to perform analysis']
            }
        elif not isinstance(metadata, dict):
            error_logger.error(f"Comprehensive analysis returned non-dict: {type(metadata)}")
            metadata = {
                'basic_info': {'Error': f'Analysis returned invalid type: {type(metadata)}'},
                'security_info': {'encrypted': False, 'revisions': 0},
                'forensic_indicators': ['Analysis failed - invalid return type'],
                'risk_assessment': 'Unknown',
                'recommendations': ['Unable to perform analysis']
            }

        # Store metadata immediately
        processing_results[job_id]['metadata'] = metadata
        forensic_logger.info("Stored comprehensive metadata in processing_results")

        processing_results[job_id]['progress'] = 30
        processing_results[job_id]['message'] = 'Initializing AI document processor...'

        # Initialize OCR client
        ocr_client = OCRClient(Config.MISTRAL_API_KEY)

        processing_results[job_id]['progress'] = 40
        processing_results[job_id]['message'] = 'Uploading document for OCR processing...'

        # Upload for OCR
        uploaded = ocr_client.upload_file(file_path)

        processing_results[job_id]['progress'] = 60
        processing_results[job_id]['message'] = 'Generating signed URL for processing...'

        # Get a signed URL
        signed_url = ocr_client.get_signed_url(uploaded.id)

        processing_results[job_id]['progress'] = 70
        processing_results[job_id]['message'] = 'Running OCR and content extraction...'

        # Run the OCR model
        ocr_response = ocr_client.run_ocr(signed_url)

        processing_results[job_id]['progress'] = 80
        processing_results[job_id]['message'] = 'Extracting and formatting tables...'

        # Process each page
        all_tables = []
        all_markdown = ""

        for page in ocr_response.pages:
            blob = json.loads(page.model_dump_json())
            markdown = blob.get("markdown", "")
            all_markdown += markdown + "\n\n"

            # Extract tables from the markdown
            tables = extract_tables_from_markdown(markdown)
            all_tables.extend(tables)

        app_logger.info(f"Extracted {len(all_tables)} tables from {len(ocr_response.pages)} pages")

        processing_results[job_id]['progress'] = 85
        processing_results[job_id]['message'] = 'Processing and formatting extracted tables...'

        # Parse and format tables
        parsed_tables = []
        output_dir = os.path.join(temp_dir, "extracted_tables")
        os.makedirs(output_dir, exist_ok=True)

        if all_tables:
            app_logger.info(f"Found {len(all_tables)} tables, starting formatting...")

            for i, table_lines in enumerate(all_tables):
                table_data = process_and_serialize(table_lines, output_dir, i)
                if table_data:
                    parsed_tables.append(table_data)
        else:
            app_logger.info("No tables found for formatting")

        processing_results[job_id]['progress'] = 95
        processing_results[job_id]['message'] = 'Finalizing analysis and preparing results...'

        # Save full text
        text_file = os.path.join(output_dir, "full_text.txt")
        with open(text_file, "w", encoding="utf-8") as f:
            f.write(all_markdown)

        # Save comprehensive forensic report
        forensic_report_file = os.path.join(output_dir, "forensic_analysis_report.json")
        with open(forensic_report_file, "w", encoding="utf-8") as f:
            json_safe_metadata = json.loads(json.dumps(metadata, indent=2, default=str, ensure_ascii=False))
            json.dump(json_safe_metadata, f, indent=2, ensure_ascii=False)

        # Handle NaN values in tables data for JSON serialization
        json_safe_tables = []
        for table in parsed_tables:
            if isinstance(table, dict):
                if 'data' in table and isinstance(table['data'], list):
                    safe_data = []
                    for row in table['data']:
                        if isinstance(row, dict):
                            safe_row = {}
                            for key, value in row.items():
                                if pd.isna(value) or value is None:
                                    safe_row[key] = ""
                                elif isinstance(value, float) and (np.isinf(value) or np.isnan(value)):
                                    safe_row[key] = ""
                                else:
                                    safe_row[key] = str(value) if not isinstance(value, (str, int, float, bool)) else value
                            safe_data.append(safe_row)
                        else:
                            safe_data.append(str(row) if row is not None else "")
                    table['data'] = safe_data
                json_safe_tables.append(table)

        # Update final results
        processing_results[job_id].update({
            'status': 'completed',
            'progress': 100,
            'message': 'Comprehensive forensic analysis complete!',
            'metadata': metadata,
            'tables': json_safe_tables,
            'text': all_markdown,
            'output_dir': output_dir,
            'text_file': text_file,
            'metadata_file': forensic_report_file
        })

        # Save job to persistent storage
        save_job_result(job_id, processing_results[job_id])

        app_logger.info(f"Job {job_id} completed successfully")

    except Exception as e:
        error_logger.error(f"Error in job {job_id}: {e}", exc_info=True)
        processing_results[job_id].update({
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()
        })

@pdf_bp.route('/status/<job_id>')
def get_status(job_id):
    """Get the status of a processing job."""
    # Try memory first, then persistent storage
    result = processing_results.get(job_id)
    if not result:
        result = load_job_result(job_id)
        if result:
            processing_results[job_id] = result  # Cache back in memory
    
    if not result:
        app_logger.warning(f"Job not found: {job_id}")
        return jsonify({'error': 'Job not found'}), 404

    result_copy = result.copy()

    # Remove sensitive data from response
    if 'file_path' in result_copy:
        del result_copy['file_path']
    if 'temp_dir' in result_copy:
        del result_copy['temp_dir']

    app_logger.debug(f"Returning status for job {job_id}: {result_copy.get('status', 'unknown')}")

    return jsonify(result_copy)

@pdf_bp.route('/download/<job_id>/<file_type>')
def download_file(job_id, file_type):
    """Download processed files."""
    # Try memory first, then check persistent storage
    result = processing_results.get(job_id)
    if not result:
        # Try to load from persistent storage
        result = load_job_result(job_id)
        if result:
            processing_results[job_id] = result  # Cache back in memory
    
    if not result:
        app_logger.warning(f"Download requested for unknown job: {job_id}")
        return "Job not found", 404

    if result['status'] != 'completed':
        app_logger.warning(f"Download requested for incomplete job: {job_id}")
        return "Job not completed", 400

    try:
        app_logger.info(f"Download requested: {file_type} for job {job_id}")

        if file_type == 'all':
            # Create ZIP file with all results
            zip_path = os.path.join(result['temp_dir'], 'comprehensive_analysis_results.zip')
            with zipfile.ZipFile(zip_path, 'w') as zipf:
                # Add all files from output directory
                for root, dirs, files in os.walk(result['output_dir']):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, result['temp_dir'])
                        zipf.write(file_path, arcname)

            app_logger.info(f"ZIP archive created: {zip_path}")
            return send_file(zip_path, as_attachment=True, download_name='comprehensive_analysis_results.zip')

        elif file_type == 'metadata':
            app_logger.info(f"Sending forensic report: {result['metadata_file']}")
            return send_file(result['metadata_file'], as_attachment=True, download_name='forensic_analysis_report.json')

        elif file_type == 'text':
            app_logger.info(f"Sending text file: {result['text_file']}")
            return send_file(result['text_file'], as_attachment=True, download_name='extracted_text.txt')

        else:
            app_logger.warning(f"Invalid file type requested: {file_type}")
            return "Invalid file type", 400

    except Exception as e:
        error_logger.error(f"Error downloading file: {e}", exc_info=True)
        return f"Error downloading file: {str(e)}", 500