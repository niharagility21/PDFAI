import os
import logging
from mistralai import Mistral

app_logger = logging.getLogger('pdf_analyzer')

class OCRClient:
    """Wrapper for Mistral OCR API calls."""
    
    def __init__(self, api_key):
        self.client = Mistral(api_key=api_key)
        app_logger.info("Mistral OCR client initialized")
    
    def upload_file(self, file_path):
        """Upload file to Mistral for OCR processing."""
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            
            uploaded = self.client.files.upload(
                file={
                    "file_name": os.path.basename(file_path),
                    "content": content
                },
                purpose="ocr"
            )
            
            app_logger.info(f"File uploaded to Mistral, file ID: {uploaded.id}")
            return uploaded
            
        except Exception as e:
            app_logger.error(f"Failed to upload file: {e}")
            raise
    
    def get_signed_url(self, file_id):
        """Get signed URL for uploaded file."""
        try:
            signed = self.client.files.get_signed_url(file_id=file_id)
            app_logger.debug(f"Generated signed URL for file ID: {file_id}")
            return signed.url
            
        except Exception as e:
            app_logger.error(f"Failed to get signed URL: {e}")
            raise
    
    def run_ocr(self, signed_url):
        """Run OCR processing on the signed URL."""
        try:
            ocr_response = self.client.ocr.process(
                model="mistral-ocr-latest",
                include_image_base64=True,
                document={
                    "type": "document_url",
                    "document_url": signed_url
                }
            )
            
            app_logger.info(f"OCR processing completed for {len(ocr_response.pages)} pages")
            return ocr_response
            
        except Exception as e:
            app_logger.error(f"Failed to run OCR: {e}")
            raise
